import pytest
from pathlib import Path
from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    _compute_percentile,
    _build_bus_merkle_tree,
)
import agy_golden_stack.bus

def test_compute_percentile():
    assert _compute_percentile([], 50.0) == 0.0
    assert _compute_percentile([42.0], 50.0) == 42.0
    
    # 3 elements: k = 2 * p/100
    # p=50 => k=1, f=1, c=1
    assert _compute_percentile([10.0, 20.0, 30.0], 50.0) == 20.0
    
    # p=25 => k=0.5, f=0, c=1
    # d0 = 10 * (1 - 0.5) = 5
    # d1 = 20 * (0.5 - 0) = 10
    # total = 15
    assert _compute_percentile([10.0, 20.0, 30.0], 25.0) == 15.0

    # p=75 => k=1.5, f=1, c=2
    # d0 = 20 * (2 - 1.5) = 10
    # d1 = 30 * (1.5 - 1) = 15
    # total = 25
    assert _compute_percentile([10.0, 20.0, 30.0], 75.0) == 25.0

def test_bus_reentrancy_and_payload_flag():
    bus = GoldenStackBus(register_defaults=False)
    
    # Payload flag
    res = bus.dispatch("Evt", payload={"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True
    assert res["ok"] is True
    assert res["total_duration_ms"] == 0.0
    
    # Active depth logic
    bus._active_depth = 1
    res = bus.dispatch("Evt")
    assert res["reentrant_short_circuit"] is True

def test_slot_priority_ordering():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S3", 30, "Slot3", lambda ev, pl, ctx: {})
    bus.register_slot("S1", 10, "Slot1", lambda ev, pl, ctx: {})
    bus.register_slot("S2", 20, "Slot2", lambda ev, pl, ctx: {})
    
    assert [s.slot_id for s in bus.slots] == ["S1", "S2", "S3"]
    
    # Test replacing a slot
    bus.register_slot("S1", 40, "Slot1_New", lambda ev, pl, ctx: {})
    assert [s.slot_id for s in bus.slots] == ["S2", "S3", "S1"]

def test_slot_exception_handling():
    bus = GoldenStackBus(register_defaults=False)
    def failing_handler(ev, pl, ctx):
        raise ValueError("Boom")
    bus.register_slot("ErrSlot", 10, "Err", failing_handler)
    
    res = bus.dispatch("TestEvent")
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "ErrSlot" in res["slot_errors"]
    assert res["slot_errors"]["ErrSlot"] == "Boom"
    
    cb = bus.get_circuit_breaker_health()
    assert cb["failure_count"] == 1
    assert cb["failure_rate"] == 1.0
    assert cb["is_tripped"] is True

def test_cua_safety_interception(monkeypatch):
    bus = GoldenStackBus(register_defaults=False)
    
    # Override the inspect function
    def mock_inspect(ev, pl, ctx):
        return {"allowed": False, "reason": "Unsafe CUA"}
    
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    res = bus.dispatch("ComputerUse_Click")
    assert res["ok"] is False
    assert res["decision"] == "block"
    assert res["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
    assert res["reason"] == "Unsafe CUA"

    res = bus.dispatch("PreToolUse", payload={"tool_name": "cu_click"})
    assert res["ok"] is False
    assert res["decision"] == "block"

def test_cua_sanitized_payload(monkeypatch):
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("Test", 10, "Test", lambda ev, pl, ctx: {})
    
    def mock_inspect(ev, pl, ctx):
        return {"allowed": True, "sanitized_payload": {"sanitized": True}}
    
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    bus.dispatch("ComputerUse_Type", payload={"original": True})
    # Since json.dumps is used in `_record_dispatch`, check if the string "sanitized" is in the output bytes
    assert b'"sanitized"' in bus._dispatched_events[-1]
    
def test_dispatch_record_json_fallback():
    bus = GoldenStackBus(register_defaults=False)
    
    # Unserializable payload
    class Unserializable:
        def __str__(self):
            return "<unserializable>"
            
    bus.dispatch("BadPayload", payload={"obj": Unserializable()})
    assert b"<unserializable>" in bus._dispatched_events[-1]

def test_circuit_breaker_health():
    bus = GoldenStackBus(register_defaults=False)
    
    cb = bus.get_circuit_breaker_health()
    assert cb["state"] == "CLOSED"
    assert cb["failure_count"] == 0
    
    # Add successes
    bus._execution_window.append({"success": True})
    bus._execution_window.append({"success": True})
    cb = bus.get_circuit_breaker_health()
    assert cb["failure_rate"] == 0.0
    
    # Add failures
    bus._execution_window.append({"success": False})
    bus._execution_window.append({"success": False})
    
    cb = bus.get_circuit_breaker_health()
    assert cb["failure_rate"] == 0.5
    assert cb["is_tripped"] is True
    assert cb["state"] == "OPEN"
    
    # Add success, pushing a failure out of a size=3 window
    bus._execution_window.append({"success": True})
    cb = bus.get_circuit_breaker_health(window_size=3)
    assert cb["failure_rate"] == 0.6667
    assert cb["is_tripped"] is True

def test_merkle_tree_build():
    # Empty
    tree = _build_bus_merkle_tree([])
    assert tree["root"] == ""
    assert tree["leaf_count"] == 0
    
    # 1 element
    leaf1 = b"leaf1"
    tree = _build_bus_merkle_tree([leaf1])
    assert tree["leaf_count"] == 1
    assert len(tree["levels"]) == 1
    
    # 2 elements (even)
    leaf2 = b"leaf2"
    tree2 = _build_bus_merkle_tree([leaf1, leaf2])
    assert tree2["leaf_count"] == 2
    assert len(tree2["levels"]) == 2
    
    # 3 elements (odd)
    leaf3 = b"leaf3"
    tree3 = _build_bus_merkle_tree([leaf1, leaf2, leaf3])
    assert tree3["leaf_count"] == 3
    
    # Compute digest from bus
    bus = GoldenStackBus(register_defaults=False)
    bus._dispatched_events = [leaf1, leaf2, leaf3]
    digest = bus.compute_bus_merkle_digest()
    assert digest["merkle_root"] == tree3["root"]

def test_telemetry_summary():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "S1", lambda ev, pl, ctx: {"decision": "allow"})
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 0
    assert summary["S1"]["allow_count"] == 0
    
    bus.dispatch("Evt1")
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 1
    assert summary["S1"]["allow_count"] == 1
    
    bus.register_slot("S2", 20, "S2", lambda ev, pl, ctx: {"decision": "block"})
    bus.dispatch("Evt2")
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 2
    assert summary["S2"]["count"] == 1
    assert summary["S2"]["block_count"] == 1
    
    bus.reset_telemetry()
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 0
    assert summary["S2"]["count"] == 0
