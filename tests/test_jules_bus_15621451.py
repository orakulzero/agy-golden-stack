import os
import sys
from pathlib import Path
import pytest

# Add src to sys.path to be able to import agy_golden_stack
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.bus import GoldenStackBus

def test_context_modification_and_decision():
    """
    Verifies that `dispatch` correctly handles the scenario where a slot handler 
    modifies the shared `context` dictionary during execution and a subsequent 
    slot in the priority chain reads that modified context value to make its 
    allow/block decision.
    """
    bus = GoldenStackBus(register_defaults=False)
    
    # Slot 1: Modifies context based on payload
    def handler1(event, payload, context):
        context["my_flag"] = payload.get("set_flag", False)
        return {"decision": "allow"}

    # Slot 2: Reads context and blocks if my_flag is True
    def handler2(event, payload, context):
        if context.get("my_flag"):
            return {"decision": "block", "reason": "my_flag is set"}
        return {"decision": "allow"}
        
    bus.register_slot("S1", 10, "setter", handler1)
    bus.register_slot("S2", 20, "reader", handler2)
    
    # Run with set_flag=False, should be allowed
    res_allow = bus.dispatch("TestEvent", {"set_flag": False})
    assert res_allow["decision"] == "allow"
    assert res_allow["ok"] is True
    assert "S1" in res_allow["executed_slots"]
    assert "S2" in res_allow["executed_slots"]
    assert res_allow["context"].get("my_flag") is False
    
    # Run with set_flag=True, should be blocked by S2
    res_block = bus.dispatch("TestEvent", {"set_flag": True})
    assert res_block["decision"] == "block"
    assert res_block["ok"] is True
    assert res_block["blocked_by"] == "S2"
    assert res_block["reason"] == "my_flag is set"
    assert "S1" in res_block["executed_slots"]
    assert "S2" in res_block["executed_slots"]
    assert res_block["context"].get("my_flag") is True

def test_golden_bus_active_reentrancy():
    """Verify that if _golden_bus_active is in payload, it short-circuits."""
    bus = GoldenStackBus(register_defaults=False)
    res = bus.dispatch("TestEvent", {"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True
    assert res["decision"] == "allow"
    
def test_dispatch_computer_use_interceptor():
    """Verify ComputerUse event inspection intercepts correctly."""
    bus = GoldenStackBus(register_defaults=False)
    
    # Should pass through normally since dummy inspect returns allowed=True
    res = bus.dispatch("ComputerUseSomething", {})
    assert res["decision"] == "allow"
    
    # Mock inspect_computer_use_bus_event to simulate a block
    import agy_golden_stack.bus as bus_mod
    orig_inspect = bus_mod.inspect_computer_use_bus_event
    try:
        bus_mod.inspect_computer_use_bus_event = lambda ev, pl, ctx: {"allowed": False, "reason": "mocked block"}
        res2 = bus.dispatch("ComputerUseBad", {})
        assert res2["decision"] == "block"
        assert res2["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
        assert res2["reason"] == "mocked block"
    finally:
        bus_mod.inspect_computer_use_bus_event = orig_inspect

def test_telemetry_and_circuit_breaker():
    """Verify telemetry summary and circuit breaker calculations."""
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "s1", lambda e, p, c: {"decision": "allow"})
    
    bus.dispatch("E1")
    bus.dispatch("E2")
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 2
    assert summary["S1"]["allow_count"] == 2
    
    cb_health = bus.get_circuit_breaker_health()
    assert cb_health["total_recorded"] == 2
    assert cb_health["failure_count"] == 0
    assert cb_health["state"] == "CLOSED"
    
    # Exception inside slot
    def handler_fail(e, p, c): raise ValueError("boom")
    bus.register_slot("S2", 20, "fail", handler_fail)
    bus.dispatch("E3")
    
    cb_health2 = bus.get_circuit_breaker_health()
    assert cb_health2["total_recorded"] == 3
    assert cb_health2["failure_count"] == 1
    
    # Circuit breaker trip threshold
    bus.dispatch("E4")
    bus.dispatch("E5")
    cb_health3 = bus.get_circuit_breaker_health()
    assert cb_health3["failure_rate"] >= 0.5
    assert cb_health3["state"] == "OPEN"
    
    bus.reset_telemetry()
    summary_after = bus.get_telemetry_summary()
    assert summary_after["S1"]["count"] == 0
    assert summary_after["S2"]["count"] == 0

def test_merkle_digest():
    """Verify Merkle root generation over dispatched events."""
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "s1", lambda e, p, c: {"decision": "allow"})
    bus.dispatch("E1", {"a": 1})
    bus.dispatch("E2", {"b": 2})
    
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 2
    assert "root" in digest
    assert len(digest["root"]) > 0

def test_priority_ordering():
    """Verify that slots are sorted in strictly ascending priority order."""
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("B", 20, "b", lambda e, p, c: {})
    bus.register_slot("A", 10, "a", lambda e, p, c: {})
    bus.register_slot("C", 30, "c", lambda e, p, c: {})
    
    assert [s.slot_id for s in bus.slots] == ["A", "B", "C"]
    
def test_handler_error_recovery():
    """Verify that if a slot handler raises an exception, it is caught and handled."""
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("E", 10, "e", lambda e, p, c: 1 / 0)
    res = bus.dispatch("Ev")
    
    # Exception makes res={"decision": "allow"} but slot_errors is populated
    assert res["ok"] is True 
    assert "E" in res["slot_errors"]
    assert "division by zero" in res["slot_errors"]["E"]
