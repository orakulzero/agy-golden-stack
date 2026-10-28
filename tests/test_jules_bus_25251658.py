import pytest
import time
from pathlib import Path
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration, _compute_percentile, _build_bus_merkle_tree
from agy_golden_stack.slots import inspect_computer_use_bus_event

def test_bus_active_while_depth_zero():
    bus = GoldenStackBus(register_defaults=False)
    # the active depth defaults to 0
    # we dispatch an event with _golden_bus_active=True in the payload
    payload = {"_golden_bus_active": True}
    res = bus.dispatch("SomeEvent", payload)
    
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert res["reentrant_short_circuit"] is True
    assert res["total_duration_ms"] == 0.0

def test_reentrant_short_circuit():
    bus = GoldenStackBus(register_defaults=False)
    # create a handler that dispatches another event
    def reentrant_handler(ev, pl, ctx):
        return bus.dispatch("NestedEvent", {})
        
    bus.register_slot("S1", 10, "reentrant", reentrant_handler)
    res = bus.dispatch("FirstEvent", {})
    assert res["ok"] is True
    assert res["decision"] == "allow"

def test_priority_ordering():
    bus = GoldenStackBus(register_defaults=False)
    exec_order = []
    bus.register_slot("S2", 20, "s2", lambda e, p, c: exec_order.append("S2"))
    bus.register_slot("S1", 10, "s1", lambda e, p, c: exec_order.append("S1"))
    bus.register_slot("S3", 10, "s3", lambda e, p, c: exec_order.append("S3")) # Same priority, sorts by slot_id
    
    assert [s.slot_id for s in bus.slots] == ["S1", "S3", "S2"]

def test_telemetry_and_reset():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "s1", lambda e, p, c: {"decision": "allow"})
    bus.register_slot("S2", 20, "s2", lambda e, p, c: {"decision": "block"})
    
    bus.dispatch("Ev1", {})
    bus.dispatch("Ev2", {}) # This will short-circuit at S2 block, so S1 gets 2 allows, S2 gets 2 blocks
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["allow_count"] == 2
    assert summary["S1"]["block_count"] == 0
    assert summary["S2"]["allow_count"] == 0
    assert summary["S2"]["block_count"] == 2
    assert summary["S1"]["count"] == 2
    
    bus.reset_telemetry()
    summary2 = bus.get_telemetry_summary()
    assert summary2["S1"]["count"] == 0
    assert summary2["S1"]["allow_count"] == 0
    assert summary2["S2"]["block_count"] == 0

def test_circuit_breaker():
    bus = GoldenStackBus(register_defaults=False)
    
    # Check 0 size
    cb = bus.get_circuit_breaker_health(window_size=0)
    assert cb["state"] == "CLOSED"
    
    def raise_err(e, p, c): raise ValueError("err")
    bus.register_slot("S_ERR", 10, "err", raise_err)
    
    # In bus.py, slot exceptions are caught and treated as `{"decision": "allow"}`
    # BUT `slot_errors` are recorded, and `is_error = len(slot_errors) > 0`
    # meaning this dispatch is treated as an error (success=False).
    bus.dispatch("EvFail", {})
    cb = bus.get_circuit_breaker_health(window_size=10)
    assert cb["is_tripped"] is True
    assert cb["state"] == "OPEN"
    
    # Test again to ensure state logic holds
    # One failure (rate=1.0)
    assert cb["failure_rate"] == 1.0

def test_merkle_digest():
    bus = GoldenStackBus(register_defaults=False)
    bus.dispatch("E1", {"a": 1})
    digest = bus.compute_bus_merkle_digest()
    assert "merkle_root" in digest
    assert digest["entry_count"] == 1
    
    bus.dispatch("E2", {"b": 2})
    digest2 = bus.compute_bus_merkle_digest()
    assert digest2["entry_count"] == 2
    assert digest2["merkle_root"] != digest["merkle_root"]

def test_percentile():
    from agy_golden_stack.bus import _compute_percentile
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([10.0], 50) == 10.0
    assert _compute_percentile([1.0, 2.0, 3.0], 50) == 2.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0], 75) == 3.25

def test_cua_intercept():
    bus = GoldenStackBus(register_defaults=False)
    
    # For test purpose, replace inspect_computer_use_bus_event if needed,
    # or rely on its default implementation from our dummy slots.py
    # `inspect_computer_use_bus_event` returns {"allowed": True, "reason": None}
    
    res = bus.dispatch("ComputerUseAction", {})
    assert res["ok"] is True
    
    res = bus.dispatch("PreToolUse", {"tool_name": "cu_click"})
    assert res["ok"] is True

def test_register_defaults():
    bus = GoldenStackBus(register_defaults=True)
    assert len(bus.slots) == 5
    assert bus.slots[0].slot_id == "P10"
    assert bus.slots[-1].slot_id == "P50"
