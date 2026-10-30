import pytest
from pathlib import Path
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration, _compute_percentile, _build_bus_merkle_tree
import math

def test_bus_dispatch_reentrant():
    bus = GoldenStackBus()
    # Mocking internal state to force re-entrancy
    bus._active_depth = 1
    result = bus.dispatch("TestEvent")
    assert result["reentrant_short_circuit"] is True
    assert result["total_duration_ms"] == 0.0

def test_bus_dispatch_reentrant_payload():
    bus = GoldenStackBus()
    result = bus.dispatch("TestEvent", {"_golden_bus_active": True})
    assert result["reentrant_short_circuit"] is True

def test_bus_dispatch_normal():
    bus = GoldenStackBus()
    result = bus.dispatch("TestEvent")
    assert result["ok"] is True
    assert result["reentrant_short_circuit"] is False
    assert "P10" in result["executed_slots"]
    assert "P50" in result["executed_slots"]

def test_bus_dispatch_cua_interceptor_block(monkeypatch):
    import agy_golden_stack.bus
    def mock_inspect(*args, **kwargs):
        return {"allowed": False, "reason": "unsafe"}
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    bus = GoldenStackBus()
    result = bus.dispatch("ComputerUseEvent")
    assert result["ok"] is False
    assert result["decision"] == "block"
    assert result["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
    assert result["reason"] == "unsafe"

def test_bus_dispatch_cua_interceptor_allow(monkeypatch):
    import agy_golden_stack.bus
    def mock_inspect(*args, **kwargs):
        return {"allowed": True, "sanitized_payload": {"safe": True}}
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    bus = GoldenStackBus()
    result = bus.dispatch("ComputerUseEvent", {"unsafe": True})
    assert result["ok"] is True
    assert result["decision"] == "allow"

def test_slot_registration_and_priority():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("P20", 20, "second", lambda ev, pl, ctx: {})
    bus.register_slot("P10", 10, "first", lambda ev, pl, ctx: {})
    
    assert bus.slots[0].slot_id == "P10"
    assert bus.slots[1].slot_id == "P20"

def test_slot_exception_handling():
    bus = GoldenStackBus(register_defaults=False)
    def failing_handler(ev, pl, ctx):
        raise ValueError("Intentional failure")
    bus.register_slot("P10", 10, "fail", failing_handler)
    
    result = bus.dispatch("TestEvent")
    assert result["ok"] is True
    assert result["slot_errors"]["P10"] == "Intentional failure"

def test_slot_block():
    bus = GoldenStackBus(register_defaults=False)
    def blocking_handler(ev, pl, ctx):
        return {"decision": "block", "reason": "blocked by rule X"}
    bus.register_slot("P10", 10, "block", blocking_handler)
    
    result = bus.dispatch("TestEvent")
    assert result["ok"] is True
    assert result["decision"] == "block"
    assert result["blocked_by"] == "P10"
    assert result["reason"] == "blocked by rule X"

def test_telemetry_summary():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("P10", 10, "test", lambda ev, pl, ctx: {})
    
    summary = bus.get_telemetry_summary()
    assert summary["P10"]["count"] == 0
    
    bus.dispatch("TestEvent")
    bus.dispatch("TestEvent")
    
    summary = bus.get_telemetry_summary()
    assert summary["P10"]["count"] == 2
    assert summary["P10"]["allow_count"] == 2

    bus.reset_telemetry()
    summary = bus.get_telemetry_summary()
    assert summary["P10"]["count"] == 0

def test_circuit_breaker_health():
    bus = GoldenStackBus(register_defaults=False)
    
    health = bus.get_circuit_breaker_health()
    assert health["state"] == "CLOSED"
    assert health["total_recorded"] == 0

    # Add successful events
    bus.register_slot("P10", 10, "test", lambda ev, pl, ctx: {})
    bus.dispatch("E1")
    bus.dispatch("E2")
    
    health = bus.get_circuit_breaker_health()
    assert health["state"] == "CLOSED"
    assert health["failure_count"] == 0
    
    # Add failing events
    def failing_handler(ev, pl, ctx):
        raise ValueError("Fail")
    
    bus.register_slot("P10", 10, "test", failing_handler)
    bus.dispatch("E3")
    bus.dispatch("E4")
    bus.dispatch("E5")
    
    health = bus.get_circuit_breaker_health()
    assert health["total_recorded"] == 5
    assert health["failure_count"] == 3
    assert health["failure_rate"] == 0.6
    assert health["state"] == "OPEN"
    assert health["is_tripped"] is True

def test_bus_merkle_digest():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("P10", 10, "test", lambda ev, pl, ctx: {})
    bus.dispatch("TestEvent", {"payload": "data1"})
    
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 1
    assert "merkle_root" in digest
    
    bus.dispatch("TestEvent", {"payload": "data2"})
    digest2 = bus.compute_bus_merkle_digest()
    assert digest2["entry_count"] == 2
    assert digest["merkle_root"] != digest2["merkle_root"]

def test_compute_percentile():
    assert _compute_percentile([], 50.0) == 0.0
    assert _compute_percentile([5.0], 50.0) == 5.0
    
    vals = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert math.isclose(_compute_percentile(vals, 0.0), 1.0)
    assert math.isclose(_compute_percentile(vals, 100.0), 5.0)
    assert math.isclose(_compute_percentile(vals, 50.0), 3.0)
    assert math.isclose(_compute_percentile(vals, 25.0), 2.0)
    assert math.isclose(_compute_percentile(vals, 75.0), 4.0)

def test_build_bus_merkle_tree():
    empty_tree = _build_bus_merkle_tree([])
    assert empty_tree["root"] == ""
    assert empty_tree["leaf_count"] == 0
    
    # 1 leaf
    tree1 = _build_bus_merkle_tree([b"test1"])
    assert tree1["leaf_count"] == 1
    
    # 3 leaves (odd number > 1)
    tree3 = _build_bus_merkle_tree([b"test1", b"test2", b"test3"])
    assert tree3["leaf_count"] == 3
