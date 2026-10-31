import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    _compute_percentile,
    _build_bus_merkle_tree,
)


def test_init_and_register_slot(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    assert len(bus.slots) == 0

    # Register slots out of order
    bus.register_slot("S2", 20, "slot2", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S3", 10, "slot3", lambda ev, pl, ctx: {"decision": "allow"}) # Same priority as S1

    # Should be S1 (10), S3 (10), S2 (20)
    assert [s.slot_id for s in bus.slots] == ["S1", "S3", "S2"]
    
    # Overwrite S2
    bus.register_slot("S2", 5, "slot2_new", lambda ev, pl, ctx: {"decision": "block"})
    assert [s.slot_id for s in bus.slots] == ["S2", "S1", "S3"]


def test_dispatch_reentrancy():
    bus = GoldenStackBus(register_defaults=False)
    
    # Trigger via payload flag
    res = bus.dispatch("SomeEvent", {"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True
    
    # Trigger via active depth
    bus._active_depth = 1
    res = bus.dispatch("SomeEvent", {})
    assert res["reentrant_short_circuit"] is True


@patch("agy_golden_stack.bus.inspect_computer_use_bus_event")
def test_dispatch_computer_use_blocked(mock_inspect):
    mock_inspect.return_value = {"allowed": False, "reason": "unsafe", "safety_flags": ["bad"]}
    bus = GoldenStackBus(register_defaults=False)
    
    res = bus.dispatch("ComputerUseAction", {})
    assert res["ok"] is False
    assert res["decision"] == "block"
    assert res["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
    assert res["reason"] == "unsafe"


@patch("agy_golden_stack.bus.inspect_computer_use_bus_event")
def test_dispatch_computer_use_sanitized(mock_inspect):
    mock_inspect.return_value = {"allowed": True, "sanitized_payload": {"clean": True}}
    bus = GoldenStackBus(register_defaults=False)
    
    called_payload = None
    def handler(ev, pl, ctx):
        nonlocal called_payload
        called_payload = pl
        return {"decision": "allow"}
        
    bus.register_slot("S1", 10, "s1", handler)
    
    res = bus.dispatch("PreToolUse", {"tool_name": "cu_browser"})
    assert res["ok"] is True
    assert called_payload == {"clean": True}


def test_dispatch_slot_execution_and_errors():
    bus = GoldenStackBus(register_defaults=False)
    
    def fail_handler(ev, pl, ctx):
        raise ValueError("Oops")
        
    def block_handler(ev, pl, ctx):
        return {"decision": "block", "reason": "blocked by me"}
        
    def not_reached_handler(ev, pl, ctx):
        return {"decision": "allow"}
        
    bus.register_slot("S1", 10, "fail", fail_handler)
    bus.register_slot("S2", 20, "block", block_handler)
    bus.register_slot("S3", 30, "unreached", not_reached_handler)
    
    res = bus.dispatch("TestEvent", {})
    
    assert res["ok"] is True  # Bus didn't crash
    assert res["decision"] == "block"
    assert res["blocked_by"] == "S2"
    assert res["reason"] == "blocked by me"
    assert "S1" in res["slot_errors"]
    assert res["slot_errors"]["S1"] == "Oops"
    assert "S3" not in res["executed_slots"]


def test_telemetry():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "s1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S2", 20, "s2", lambda ev, pl, ctx: {"decision": "block"})
    
    bus.dispatch("E1", {})
    bus.dispatch("E2", {})  # S2 always blocks
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 2
    assert summary["S1"]["allow_count"] == 2
    assert summary["S1"]["block_count"] == 0
    assert summary["S2"]["count"] == 2
    assert summary["S2"]["allow_count"] == 0
    assert summary["S2"]["block_count"] == 2
    
    # Test reset
    bus.reset_telemetry()
    summary2 = bus.get_telemetry_summary()
    assert summary2["S1"]["count"] == 0
    assert summary2["S1"]["allow_count"] == 0


def test_circuit_breaker():
    bus = GoldenStackBus(register_defaults=False)
    
    # Empty
    cb = bus.get_circuit_breaker_health(10)
    assert cb["state"] == "CLOSED"
    assert cb["is_tripped"] is False
    
    # Record success and errors
    bus._record_dispatch("E1", {}, {})
    bus._record_dispatch("E2", {}, {"S1": "error"})
    
    cb = bus.get_circuit_breaker_health(10)
    assert cb["total_recorded"] == 2
    assert cb["failure_count"] == 1
    assert cb["failure_rate"] == 0.5
    assert cb["is_tripped"] is True
    assert cb["state"] == "OPEN"
    
    # Record more success to lower failure rate below 0.5
    bus._record_dispatch("E3", {}, {})
    cb = bus.get_circuit_breaker_health(10)
    assert cb["failure_rate"] == round(1/3, 4)
    assert cb["is_tripped"] is False


class UnserializableObject:
    def __str__(self):
        raise ValueError("Cannot serialize me")

def test_record_dispatch_json_fallback():
    bus = GoldenStackBus(register_defaults=False)
    # The _record_dispatch should fallback to string representation for unserializable
    bus._record_dispatch("Test", {"obj": UnserializableObject()}, {})
    assert len(bus._dispatched_events) == 1
    assert b"Test:" in bus._dispatched_events[0]


def test_compute_percentile():
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([1.0], 50) == 1.0
    assert _compute_percentile([1.0, 2.0], 50) == 1.5
    assert _compute_percentile([1.0, 2.0, 3.0], 50) == 2.0
    # Boundary p=100
    assert _compute_percentile([1.0, 2.0, 3.0], 100) == 3.0


def test_build_bus_merkle_tree():
    # Empty
    res0 = _build_bus_merkle_tree([])
    assert res0["root"] == ""
    
    # One leaf
    l1 = b"leaf1"
    res1 = _build_bus_merkle_tree([l1])
    assert res1["leaf_count"] == 1
    
    # Three leaves (tests odd number duplication)
    res3 = _build_bus_merkle_tree([b"l1", b"l2", b"l3"])
    assert res3["leaf_count"] == 3
    assert len(res3["levels"]) > 1

def test_compute_bus_merkle_digest():
    bus = GoldenStackBus(register_defaults=False)
    res = bus.compute_bus_merkle_digest()
    assert res["entry_count"] == 0
    assert res["merkle_root"] == ""
    
    bus._record_dispatch("E1", {}, {})
    res2 = bus.compute_bus_merkle_digest()
    assert res2["entry_count"] == 1
    assert res2["merkle_root"] != ""
