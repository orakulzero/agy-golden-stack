"""Comprehensive tests for GoldenStackBus."""

from __future__ import annotations

import math
from unittest.mock import patch, MagicMock
import pytest
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration, _compute_percentile, _build_bus_merkle_tree


def test_computer_use_short_circuit_on_false():
    """Test that ComputerUse prefixed event with allowed=False short-circuits and skips slots."""
    bus = GoldenStackBus(register_defaults=True)
    with patch("agy_golden_stack.bus.inspect_computer_use_bus_event") as mock_inspect:
        mock_inspect.return_value = {
            "allowed": False,
            "reason": "Security violation",
            "safety_flags": ["SUSPICIOUS_CUA_ACTION"]
        }
        
        result = bus.dispatch("ComputerUseDoAction", payload={"foo": "bar"})
        
        assert not result["ok"]
        assert result["decision"] == "block"
        assert result["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
        assert result["reason"] == "Security violation"
        assert result["safety_flags"] == ["SUSPICIOUS_CUA_ACTION"]
        assert len(result["executed_slots"]) == 0
        
        # Telemetry should NOT be incremented for any slots
        summary = bus.get_telemetry_summary()
        for slot in ["P10", "P20", "P30", "P40", "P50"]:
            assert summary[slot]["allow_count"] == 0
            assert summary[slot]["block_count"] == 0

def test_pre_tool_use_cu_prefix_short_circuit():
    """Test that PreToolUse with tool_name starting with cu_ also intercepts."""
    bus = GoldenStackBus(register_defaults=True)
    with patch("agy_golden_stack.bus.inspect_computer_use_bus_event") as mock_inspect:
        mock_inspect.return_value = {
            "allowed": False,
            "reason": "PreToolUse blocked"
        }
        
        result = bus.dispatch("PreToolUse", payload={"tool_name": "cu_click"})
        assert not result["ok"]
        assert result["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
        assert len(result["executed_slots"]) == 0

def test_computer_use_allowed_and_sanitized():
    """Test that allowed CUA event proceeds and payload can be sanitized."""
    bus = GoldenStackBus(register_defaults=False)
    
    # We will record what payload the slot sees
    seen_payload = {}
    def dummy_handler(ev, pl, ctx):
        seen_payload.update(pl)
        return {"decision": "allow"}
        
    bus.register_slot("TEST1", 10, "test", dummy_handler)
    
    with patch("agy_golden_stack.bus.inspect_computer_use_bus_event") as mock_inspect:
        mock_inspect.return_value = {
            "allowed": True,
            "sanitized_payload": {"foo": "sanitized_bar"}
        }
        
        result = bus.dispatch("ComputerUseAction", payload={"foo": "bar"})
        assert result["ok"]
        assert seen_payload == {"foo": "sanitized_bar"}
        assert "TEST1" in result["executed_slots"]

def test_reentrancy_guard():
    """Test that recursive dispatch calls short circuit."""
    bus = GoldenStackBus(register_defaults=False)
    
    dispatches = []
    
    def reentrant_handler(ev, pl, ctx):
        # This will trigger a reentrant call
        res = bus.dispatch("NestedEvent", {})
        dispatches.append(res)
        return {"decision": "allow"}
        
    bus.register_slot("RE", 10, "reentrant", reentrant_handler)
    
    res = bus.dispatch("MainEvent", {})
    assert res["ok"]
    assert len(dispatches) == 1
    nested_res = dispatches[0]
    assert nested_res["reentrant_short_circuit"] is True
    assert nested_res["total_duration_ms"] == 0.0

def test_reentrancy_guard_explicit_flag():
    """Test reentrancy guard using explicit flag _golden_bus_active."""
    bus = GoldenStackBus(register_defaults=False)
    res = bus.dispatch("AnyEvent", {"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True

def test_slot_priority_ordering():
    """Test that slots are executed in ascending priority order."""
    bus = GoldenStackBus(register_defaults=False)
    
    order = []
    
    bus.register_slot("S50", 50, "p50", lambda ev, pl, ctx: order.append("S50") or {"decision": "allow"})
    bus.register_slot("S10", 10, "p10", lambda ev, pl, ctx: order.append("S10") or {"decision": "allow"})
    bus.register_slot("S30", 30, "p30", lambda ev, pl, ctx: order.append("S30") or {"decision": "allow"})
    
    bus.dispatch("Ev", {})
    assert order == ["S10", "S30", "S50"]
    assert [s.slot_id for s in bus.slots] == ["S10", "S30", "S50"]

def test_slot_blocking():
    """Test that a slot can block the execution pipeline."""
    bus = GoldenStackBus(register_defaults=False)
    
    bus.register_slot("S10", 10, "p10", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S20", 20, "p20", lambda ev, pl, ctx: {"decision": "block", "reason": "blocked by S20"})
    bus.register_slot("S30", 30, "p30", lambda ev, pl, ctx: {"decision": "allow"})
    
    res = bus.dispatch("Ev", {})
    assert res["decision"] == "block"
    assert res["blocked_by"] == "S20"
    assert res["executed_slots"] == ["S10", "S20"] # S30 is skipped
    
    summary = bus.get_telemetry_summary()
    assert summary["S10"]["allow_count"] == 1
    assert summary["S20"]["block_count"] == 1
    assert summary["S30"]["allow_count"] == 0

def test_slot_exception_handling():
    """Test that an exception in a slot does not crash the bus but records an error."""
    bus = GoldenStackBus(register_defaults=False)
    
    def crash_handler(ev, pl, ctx):
        raise ValueError("Boom")
        
    bus.register_slot("CRASH", 10, "crash", crash_handler)
    
    res = bus.dispatch("Ev", {})
    assert res["ok"]
    assert res["decision"] == "allow"
    assert "CRASH" in res["slot_errors"]
    assert "Boom" in res["slot_errors"]["CRASH"]
    
    # Verify circuit breaker health reflects this error
    cb = bus.get_circuit_breaker_health()
    assert cb["failure_count"] == 1
    assert cb["failure_rate"] == 1.0
    assert cb["is_tripped"] is True
    assert cb["state"] == "OPEN"

def test_circuit_breaker_sliding_window():
    """Test the circuit breaker window size logic."""
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S10", 10, "p10", lambda ev, pl, ctx: {"decision": "allow"})
    
    for i in range(10):
        bus.dispatch("Ev", {})
        
    cb = bus.get_circuit_breaker_health(window_size=5)
    assert cb["total_recorded"] == 5
    assert cb["failure_count"] == 0
    assert cb["is_tripped"] is False

    bus.register_slot("S10", 10, "p10", lambda ev, pl, ctx: dict(raise_err=eval("1/0")))
    for i in range(5):
        bus.dispatch("Ev", {})

    cb = bus.get_circuit_breaker_health(window_size=10)
    assert cb["total_recorded"] == 10
    assert cb["failure_count"] == 5
    assert cb["is_tripped"] is True

def test_telemetry_and_reset():
    """Test computing telemetry and resetting it."""
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S10", 10, "p10", lambda ev, pl, ctx: {"decision": "allow"})
    
    bus.dispatch("Ev", {})
    bus.dispatch("Ev", {})
    
    summary = bus.get_telemetry_summary()
    assert summary["S10"]["count"] == 2
    
    bus.reset_telemetry()
    summary_after = bus.get_telemetry_summary()
    assert summary_after["S10"]["count"] == 0

def test_percentile_computation():
    """Test percentile function logic on boundary arrays."""
    assert _compute_percentile([], 50.0) == 0.0
    assert _compute_percentile([42.0], 50.0) == 42.0
    
    # [10, 20, 30]
    # k = 2 * 0.5 = 1
    assert _compute_percentile([10.0, 20.0, 30.0], 50.0) == 20.0
    # k = 2 * 0.95 = 1.9
    # d = 0.9. f = 1. c = 2. 
    assert math.isclose(_compute_percentile([10.0, 20.0, 30.0], 95.0), 29.0)

def test_merkle_tree():
    """Test merkle tree computation."""
    tree_empty = _build_bus_merkle_tree([])
    assert tree_empty["root"] == ""
    
    leaf1 = b"test1"
    leaf2 = b"test2"
    leaf3 = b"test3"
    
    tree = _build_bus_merkle_tree([leaf1, leaf2, leaf3])
    assert tree["leaf_count"] == 3
    assert len(tree["levels"]) > 1

def test_compute_bus_merkle_digest():
    """Test GoldenStackBus merkle digest integration."""
    bus = GoldenStackBus(register_defaults=False)
    
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 0
    assert digest["merkle_root"] == ""
    
    bus.dispatch("Ev", {"k": "v"})
    digest2 = bus.compute_bus_merkle_digest()
    assert digest2["entry_count"] == 1
    assert digest2["merkle_root"] != ""
