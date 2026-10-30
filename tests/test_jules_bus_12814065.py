import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import pytest
from pathlib import Path
from typing import Any, Dict

from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    _compute_percentile,
    _build_bus_merkle_tree
)

def test_compute_percentile():
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([1.0], 50) == 1.0
    
    # [1.0, 2.0, 3.0, 4.0, 5.0]
    # k = (5-1) * 0.5 = 2.0 -> index 2 -> 3.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 0) == 1.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 100) == 5.0

    # Test interpolation
    assert _compute_percentile([1.0, 2.0, 3.0], 25) == 1.5

def test_build_bus_merkle_tree():
    # Empty
    tree = _build_bus_merkle_tree([])
    assert tree["root"] == ""
    assert tree["leaf_count"] == 0
    assert tree["levels"] == []

    # 1 element
    tree = _build_bus_merkle_tree([b"test"])
    assert tree["leaf_count"] == 1
    assert len(tree["levels"]) == 1

    # 2 elements
    tree = _build_bus_merkle_tree([b"test1", b"test2"])
    assert tree["leaf_count"] == 2
    assert len(tree["levels"]) == 2

    # 3 elements (odd)
    tree = _build_bus_merkle_tree([b"test1", b"test2", b"test3"])
    assert tree["leaf_count"] == 3
    assert len(tree["levels"]) == 3

def test_bus_init_defaults(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=True)
    assert len(bus.slots) == 5
    assert [s.slot_id for s in bus.slots] == ["P10", "P20", "P30", "P40", "P50"]

def test_register_slot(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    bus.register_slot("S2", 20, "slot2", lambda e, p, c: {})
    bus.register_slot("S1", 10, "slot1", lambda e, p, c: {})
    bus.register_slot("S3", 30, "slot3", lambda e, p, c: {})
    
    assert [s.slot_id for s in bus.slots] == ["S1", "S2", "S3"]
    
    # Overwrite existing slot
    bus.register_slot("S2", 5, "slot2_new", lambda e, p, c: {})
    assert [s.slot_id for s in bus.slots] == ["S2", "S1", "S3"]

def test_dispatch_reentrant(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    # Re-entrancy flag in payload
    res = bus.dispatch("event", {"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True
    assert res["ok"] is True

    # Active depth > 0
    bus._active_depth = 1
    res = bus.dispatch("event", {})
    assert res["reentrant_short_circuit"] is True
    assert res["ok"] is True

def test_dispatch_computer_use_interceptor(monkeypatch, tmp_path):
    import agy_golden_stack.bus
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", lambda ev, pl, ctx: {"allowed": False, "reason": "blocked", "safety_flags": ["X"]})
    
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    res = bus.dispatch("ComputerUse", {})
    assert res["ok"] is False
    assert res["decision"] == "block"
    assert res["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"
    assert res["reason"] == "blocked"

def test_dispatch_computer_use_sanitized(monkeypatch, tmp_path):
    import agy_golden_stack.bus
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", lambda ev, pl, ctx: {"allowed": True, "sanitized_payload": {"sanitized": True}})
    
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    # Record payload sent to handler
    received_pl = {}
    bus.register_slot("S1", 10, "s1", lambda e, p, c: received_pl.update(p) or {})
    
    res = bus.dispatch("ComputerUse", {"original": True})
    assert res["ok"] is True
    assert received_pl.get("sanitized") is True
    assert "original" not in received_pl

def test_dispatch_slot_exception(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    def raise_exc(e, p, c):
        raise ValueError("test exception")
        
    bus.register_slot("S1", 10, "s1", raise_exc)
    res = bus.dispatch("event", {})
    
    # Should not crash, and should be considered 'allow' with error recorded
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "S1" in res["slot_errors"]
    assert "test exception" in res["slot_errors"]["S1"]

def test_dispatch_slot_block(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    bus.register_slot("S1", 10, "s1", lambda e, p, c: {"decision": "allow"})
    bus.register_slot("S2", 20, "s2", lambda e, p, c: {"decision": "block", "reason": "blocked by S2"})
    bus.register_slot("S3", 30, "s3", lambda e, p, c: {"decision": "allow"}) # Should not execute
    
    res = bus.dispatch("event", {})
    
    assert res["ok"] is True
    assert res["decision"] == "block"
    assert res["blocked_by"] == "S2"
    assert "S1" in res["executed_slots"]
    assert "S2" in res["executed_slots"]
    assert "S3" not in res["executed_slots"]

def test_telemetry_summary_and_reset(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    bus.register_slot("S1", 10, "s1", lambda e, p, c: {})
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 0
    assert summary["S1"]["allow_count"] == 0
    
    bus.dispatch("event", {})
    
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 1
    assert summary["S1"]["allow_count"] == 1
    
    bus.reset_telemetry()
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 0
    assert summary["S1"]["allow_count"] == 0

def test_circuit_breaker(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    # Initial state
    cb = bus.get_circuit_breaker_health()
    assert cb["state"] == "CLOSED"
    assert cb["is_tripped"] is False
    
    def raise_exc(e, p, c):
        raise ValueError("err")
        
    bus.register_slot("S1", 10, "s1", raise_exc)
    
    # Add one failure (exc -> error)
    bus.dispatch("event", {})
    
    cb = bus.get_circuit_breaker_health(window_size=1)
    assert cb["state"] == "OPEN"
    assert cb["is_tripped"] is True
    assert cb["failure_count"] == 1

def test_bus_merkle_digest(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    bus.register_slot("S1", 10, "s1", lambda e, p, c: {})
    
    digest1 = bus.compute_bus_merkle_digest()
    assert digest1["entry_count"] == 0
    
    bus.dispatch("event1", {"data": 1})
    bus.dispatch("event2", {"data": 2})
    
    digest2 = bus.compute_bus_merkle_digest()
    assert digest2["entry_count"] == 2
    assert digest2["merkle_root"] != ""
    assert "tree" in digest2

def test_record_dispatch_unserializable_payload(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    class Unserializable:
        pass
        
    bus.dispatch("event1", {"data": Unserializable()})
    
    # Should fallback to str() and not crash
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 1
