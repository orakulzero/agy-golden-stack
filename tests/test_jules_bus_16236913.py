import pytest
from pathlib import Path
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration, _compute_percentile, _build_bus_merkle_tree
import time
import math
import json
import hashlib

def test_bus_init():
    bus = GoldenStackBus(register_defaults=False)
    assert len(bus.slots) == 0

def test_bus_init_defaults(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=True)
    assert len(bus.slots) == 5
    assert [s.slot_id for s in bus.slots] == ["P10", "P20", "P30", "P40", "P50"]

def test_bus_dispatch_reentrancy():
    bus = GoldenStackBus(register_defaults=False)
    # Simulate re-entrancy
    bus._active_depth = 1
    result = bus.dispatch("TestEvent")
    assert result["reentrant_short_circuit"] is True
    assert result["decision"] == "allow"
    assert result["total_duration_ms"] == 0.0

    bus._active_depth = 0
    result = bus.dispatch("TestEvent", {"_golden_bus_active": True})
    assert result["reentrant_short_circuit"] is True

def test_bus_dispatch_computer_use_interceptor(monkeypatch):
    # Mocking inspect_computer_use_bus_event to simulate a block
    import agy_golden_stack.bus
    
    def mock_inspect(ev, pl, ctx):
        return {"allowed": False, "reason": "Unsafe command", "safety_flags": ["bad_cmd"]}
    
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    bus = GoldenStackBus(register_defaults=False)
    result = bus.dispatch("ComputerUse", {})
    
    assert result["ok"] is False
    assert result["decision"] == "block"
    assert result["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
    assert result["reason"] == "Unsafe command"
    assert "bad_cmd" in result["safety_flags"]

def test_bus_dispatch_computer_use_interceptor_pretooluse(monkeypatch):
    import agy_golden_stack.bus
    
    def mock_inspect(ev, pl, ctx):
        return {"allowed": False, "reason": "Unsafe command", "safety_flags": ["bad_cmd"]}
    
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    bus = GoldenStackBus(register_defaults=False)
    result = bus.dispatch("PreToolUse", {"tool_name": "cu_bash"})
    
    assert result["ok"] is False
    assert result["decision"] == "block"
    assert result["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"

def test_bus_dispatch_computer_use_interceptor_sanitized(monkeypatch):
    # Mocking inspect_computer_use_bus_event to simulate sanitized payload
    import agy_golden_stack.bus
    
    def mock_inspect(ev, pl, ctx):
        return {"allowed": True, "sanitized_payload": {"sanitized": True}}
    
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", mock_inspect)
    
    bus = GoldenStackBus(register_defaults=False)
    
    # Store received payload in closure to check it later
    received = {}
    def dummy_handler(ev, pl, ctx):
        received.update(pl)
        return {"decision": "allow"}
    
    bus.register_slot("P1", 1, "test", dummy_handler)
    result = bus.dispatch("ComputerUse", {"unsafe": True})
    
    assert result["ok"] is True
    assert result["decision"] == "allow"
    assert received == {"sanitized": True}
    
def test_bus_dispatch_exception_in_slot():
    bus = GoldenStackBus(register_defaults=False)
    def failing_handler(ev, pl, ctx):
        raise ValueError("Simulated Failure")
    
    bus.register_slot("P99", 99, "failing", failing_handler)
    result = bus.dispatch("TestEvent")
    assert result["ok"] is True
    assert result["decision"] == "allow"
    assert "P99" in result["slot_errors"]
    assert "Simulated Failure" in result["slot_errors"]["P99"]

def test_bus_dispatch_block_decision():
    bus = GoldenStackBus(register_defaults=False)
    def blocking_handler(ev, pl, ctx):
        return {"decision": "block", "reason": "Blocked by tests"}
    
    bus.register_slot("P1", 1, "blocking", blocking_handler)
    result = bus.dispatch("TestEvent")
    assert result["ok"] is True
    assert result["decision"] == "block"
    assert result["blocked_by"] == "P1"
    assert result["reason"] == "Blocked by tests"
    assert result["executed_slots"] == ["P1"]
    
def test_bus_circuit_breaker():
    bus = GoldenStackBus(register_defaults=False)
    # inject execution records
    bus._execution_window = [
        {"success": False},
        {"success": False},
        {"success": True}
    ]
    cb = bus.get_circuit_breaker_health(window_size=3)
    assert math.isclose(cb["failure_rate"], 2/3, rel_tol=1e-3)
    assert cb["is_tripped"] is True
    assert cb["state"] == "OPEN"

    cb = bus.get_circuit_breaker_health(window_size=0)
    assert math.isclose(cb["failure_rate"], 2/3, rel_tol=1e-3)
    
    cb_empty = GoldenStackBus(register_defaults=False).get_circuit_breaker_health(window_size=3)
    assert cb_empty["failure_rate"] == 0.0
    assert cb_empty["state"] == "CLOSED"
    assert cb_empty["total_recorded"] == 0

def test_bus_telemetry():
    bus = GoldenStackBus(register_defaults=False)
    
    def blocking_handler(ev, pl, ctx):
        return {"decision": "block"}
        
    bus.register_slot("P1", 1, "test_allow", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("P2", 2, "test_block", blocking_handler)
    bus.dispatch("TestEvent")
    
    summary = bus.get_telemetry_summary()
    assert summary["P1"]["count"] == 1
    assert summary["P1"]["allow_count"] == 1
    assert summary["P1"]["block_count"] == 0
    
    assert summary["P2"]["count"] == 1
    assert summary["P2"]["allow_count"] == 0
    assert summary["P2"]["block_count"] == 1
    
    # Check metrics existence
    for key in ["min_ms", "avg_ms", "p50_ms", "p95_ms", "max_ms"]:
        assert key in summary["P1"]
    
    bus.reset_telemetry()
    summary = bus.get_telemetry_summary()
    assert summary["P1"]["count"] == 0
    assert summary["P1"]["allow_count"] == 0
    assert summary["P1"]["block_count"] == 0
    assert summary["P1"]["min_ms"] == 0.0

def test_compute_percentile():
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([10.0], 50) == 10.0
    vals = [1.0, 2.0, 3.0, 4.0]
    assert _compute_percentile(vals, 50) == 2.5
    
    # Boundary check for p=100 or when c >= len(sorted_vals)
    assert _compute_percentile(vals, 100) == 4.0
    assert _compute_percentile(vals, 0) == 1.0
    
    # p95
    vals = list(range(1, 101))
    assert math.isclose(_compute_percentile(vals, 95), 95.05, rel_tol=1e-3)

def test_merkle_tree_empty():
    tree = _build_bus_merkle_tree([])
    assert tree["root"] == ""
    assert tree["leaf_count"] == 0
    assert tree["levels"] == []

def test_merkle_tree_single():
    tree = _build_bus_merkle_tree([b"test"])
    assert tree["leaf_count"] == 1
    assert tree["root"] != ""
    assert len(tree["levels"]) == 1
    
def test_merkle_tree_odd_number():
    tree = _build_bus_merkle_tree([b"t1", b"t2", b"t3"])
    assert tree["leaf_count"] == 3
    assert tree["root"] != ""
    assert len(tree["levels"]) > 1

def test_bus_compute_merkle_digest():
    bus = GoldenStackBus(register_defaults=False)
    bus.dispatch("Event1")
    bus.dispatch("Event2")
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 2
    assert digest["root"] != ""

def test_bus_record_dispatch_unserializable():
    bus = GoldenStackBus(register_defaults=False)
    
    class Unserializable:
        pass
    
    bus._record_dispatch("TestEvent", {"bad": Unserializable()}, {})
    assert len(bus._dispatched_events) == 1
    # Check that fallback happened (it encodes f"{event_name}:{str(payload)}")
    assert b"TestEvent" in bus._dispatched_events[0]

def test_bus_dispatch_telemetry_missing_sid():
    bus = GoldenStackBus(register_defaults=False)
    def ok_handler(ev, pl, ctx):
        return {"decision": "allow"}
    
    bus.register_slot("P1", 1, "test", ok_handler)
    # Remove sid from telemetry internally to trigger line 193-194
    del bus._telemetry_timings["P1"]
    bus.dispatch("TestEvent")
    summary = bus.get_telemetry_summary()
    assert summary["P1"]["count"] == 1

def test_bus_record_dispatch_unserializable_exception(monkeypatch):
    bus = GoldenStackBus(register_defaults=False)
    
    # Mock json.dumps to throw an exception that bypasses default=str
    import json
    def mock_dumps(*args, **kwargs):
        raise TypeError("Not JSON serializable")
    
    monkeypatch.setattr(json, "dumps", mock_dumps)
    
    bus._record_dispatch("TestEvent", {"bad": "data"}, {})
    assert len(bus._dispatched_events) == 1
    assert b"TestEvent" in bus._dispatched_events[0]
