import pytest
from unittest.mock import patch, MagicMock
from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    _build_bus_merkle_tree,
    _compute_percentile,
)

@pytest.fixture
def empty_bus():
    return GoldenStackBus(register_defaults=False)

def test_bus_initialization():
    bus = GoldenStackBus(register_defaults=False)
    assert bus._active_depth == 0
    assert len(bus.slots) == 0

def test_register_slot_sorting(empty_bus):
    empty_bus.register_slot("S2", 20, "slot2", lambda ev, pl, ctx: {})
    empty_bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {})
    empty_bus.register_slot("S3", 30, "slot3", lambda ev, pl, ctx: {})
    
    assert [s.slot_id for s in empty_bus.slots] == ["S1", "S2", "S3"]

def test_reentrancy_guard(empty_bus):
    # Test internal re-entrancy depth
    empty_bus._active_depth = 1
    res = empty_bus.dispatch("AnyEvent")
    assert res["reentrant_short_circuit"] is True
    assert res["ok"] is True
    assert res["decision"] == "allow"
    
    # Test payload flag
    empty_bus._active_depth = 0
    res2 = empty_bus.dispatch("AnyEvent", {"_golden_bus_active": True})
    assert res2["reentrant_short_circuit"] is True

def test_computer_use_interceptor(empty_bus):
    with patch("agy_golden_stack.bus.inspect_computer_use_bus_event") as mock_inspect:
        mock_inspect.return_value = {
            "allowed": False,
            "reason": "Dangerous command",
            "safety_flags": ["rm_rf"]
        }
        res = empty_bus.dispatch("ComputerUse_Execute", {"command": "rm -rf /"})
        assert res["ok"] is False
        assert res["decision"] == "block"
        assert res["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
        assert res["reason"] == "Dangerous command"
        assert "rm_rf" in res["safety_flags"]

def test_computer_use_interceptor_allowed_with_sanitization(empty_bus):
    with patch("agy_golden_stack.bus.inspect_computer_use_bus_event") as mock_inspect:
        mock_inspect.return_value = {
            "allowed": True,
            "sanitized_payload": {"command": "ls"}
        }
        
        def check_payload(ev, pl, ctx):
            assert pl["command"] == "ls"
            return {"decision": "allow"}
            
        empty_bus.register_slot("S1", 10, "s1", check_payload)
        res = empty_bus.dispatch("ComputerUse_Execute", {"command": "ls -la"})
        assert res["ok"] is True

def test_slot_execution_allow(empty_bus):
    empty_bus.register_slot("S1", 10, "s1", lambda ev, pl, ctx: {"decision": "allow"})
    res = empty_bus.dispatch("TestEvent")
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "S1" in res["executed_slots"]
    assert "S1" in res["slot_timings_ms"]

def test_slot_execution_block(empty_bus):
    empty_bus.register_slot("S1", 10, "s1", lambda ev, pl, ctx: {"decision": "allow"})
    empty_bus.register_slot("S2", 20, "s2", lambda ev, pl, ctx: {"decision": "block", "reason": "policy"})
    empty_bus.register_slot("S3", 30, "s3", lambda ev, pl, ctx: {"decision": "allow"})
    
    res = empty_bus.dispatch("TestEvent")
    assert res["ok"] is True
    assert res["decision"] == "block"
    assert res["blocked_by"] == "S2"
    assert res["reason"] == "policy"
    # S3 should not be executed
    assert "S3" not in res["executed_slots"]

def test_slot_exception_handling(empty_bus):
    def failing_slot(ev, pl, ctx):
        raise RuntimeError("Slot crashed")
        
    empty_bus.register_slot("S1", 10, "s1", failing_slot)
    res = empty_bus.dispatch("TestEvent")
    
    assert res["ok"] is True
    assert res["decision"] == "allow"  # default to allow on error
    assert res["slot_errors"]["S1"] == "Slot crashed"

def test_telemetry_summary_and_reset(empty_bus):
    empty_bus.register_slot("S1", 10, "s1", lambda ev, pl, ctx: {"decision": "allow"})
    empty_bus.dispatch("Event1")
    empty_bus.dispatch("Event2")
    
    summary = empty_bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 2
    assert summary["S1"]["allow_count"] == 2
    assert summary["S1"]["block_count"] == 0
    assert summary["S1"]["avg_ms"] >= 0
    
    empty_bus.reset_telemetry()
    summary2 = empty_bus.get_telemetry_summary()
    assert summary2["S1"]["count"] == 0

def test_circuit_breaker(empty_bus):
    # Initially closed
    cb = empty_bus.get_circuit_breaker_health(window_size=10)
    assert cb["state"] == "CLOSED"
    assert cb["failure_count"] == 0
    
    # Add a failure (exception in slot)
    def failing_slot(ev, pl, ctx):
        raise ValueError("Error")
    empty_bus.register_slot("S1", 10, "s1", failing_slot)
    
    # 1 failure
    empty_bus.dispatch("Event1")
    cb = empty_bus.get_circuit_breaker_health(window_size=10)
    assert cb["state"] == "OPEN"
    assert cb["failure_count"] == 1
    assert cb["is_tripped"] is True

def test_merkle_digest(empty_bus):
    empty_bus.register_slot("S1", 10, "s1", lambda ev, pl, ctx: {"decision": "allow"})
    empty_bus.dispatch("Event1", {"a": 1})
    empty_bus.dispatch("Event2", {"b": 2})
    
    digest = empty_bus.compute_bus_merkle_digest()
    assert "merkle_root" in digest
    assert digest["entry_count"] == 2
    assert len(digest["tree"]["levels"]) > 1

def test_build_bus_merkle_tree():
    # Empty
    tree = _build_bus_merkle_tree([])
    assert tree["root"] == ""
    
    # Odd number of leaves
    l1 = b"leaf1"
    l2 = b"leaf2"
    l3 = b"leaf3"
    tree = _build_bus_merkle_tree([l1, l2, l3])
    assert tree["leaf_count"] == 3
    assert len(tree["levels"]) > 1
    
    # Verify deterministic root for single leaf
    import hashlib
    single_tree = _build_bus_merkle_tree([l1])
    expected_root = hashlib.sha256(b"\x00" + l1).hexdigest()
    assert single_tree["root"] == expected_root

def test_compute_percentile():
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([10.0], 50) == 10.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 100) == 5.0
    
    # Interpolation case
    vals = [10.0, 20.0]
    assert _compute_percentile(vals, 50) == 15.0

def test_pre_tool_use_interceptor(empty_bus):
    with patch("agy_golden_stack.bus.inspect_computer_use_bus_event") as mock_inspect:
        mock_inspect.return_value = {"allowed": False, "reason": "blocked"}
        res = empty_bus.dispatch("PreToolUse", {"tool_name": "cu_execute"})
        assert res["decision"] == "block"
        assert res["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"

def test_record_dispatch_unserializable(empty_bus):
    class Unserializable:
        def __str__(self):
            return "bad_obj"
    
    empty_bus.register_slot("S1", 10, "s1", lambda ev, pl, ctx: {"decision": "allow"})
    empty_bus.dispatch("TestEvent", {"obj": Unserializable()})
    
    # Should fallback to str representation without crashing
    digest = empty_bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 1
