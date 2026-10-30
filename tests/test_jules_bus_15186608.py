import pytest
from pathlib import Path
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration, _compute_percentile, _build_bus_merkle_tree
import time

def test_bus_initialization_and_default_slots(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path)
    assert len(bus.slots) == 5
    slot_ids = [slot.slot_id for slot in bus.slots]
    assert slot_ids == ["P10", "P20", "P30", "P40", "P50"]
    assert bus.workspace_root == tmp_path.resolve()

def test_custom_slot_registration_and_priority():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S3", 30, "slot3", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S2", 20, "slot2", lambda ev, pl, ctx: {"decision": "allow"})
    
    assert len(bus.slots) == 3
    assert [s.slot_id for s in bus.slots] == ["S1", "S2", "S3"]
    assert [s.priority for s in bus.slots] == [10, 20, 30]

def test_dispatch_allow_all():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S2", 20, "slot2", lambda ev, pl, ctx: {"decision": "allow"})
    
    res = bus.dispatch("TestEvent", {"data": 123})
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert res["executed_slots"] == ["S1", "S2"]
    assert res["blocked_by"] is None

def test_dispatch_block_early():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.register_slot("S2", 20, "slot2", lambda ev, pl, ctx: {"decision": "block", "reason": "blocked by S2"})
    bus.register_slot("S3", 30, "slot3", lambda ev, pl, ctx: {"decision": "allow"})
    
    res = bus.dispatch("TestEvent", {"data": 123})
    assert res["ok"] is True
    assert res["decision"] == "block"
    assert res["executed_slots"] == ["S1", "S2"]
    assert res["blocked_by"] == "S2"
    assert res["reason"] == "blocked by S2"

def test_dispatch_exception_handling():
    bus = GoldenStackBus(register_defaults=False)
    
    def failing_handler(ev, pl, ctx):
        raise ValueError("Something went wrong")
        
    bus.register_slot("S1", 10, "slot1", failing_handler)
    bus.register_slot("S2", 20, "slot2", lambda ev, pl, ctx: {"decision": "allow"})
    
    res = bus.dispatch("TestEvent")
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "S1" in res["slot_errors"]
    assert res["slot_errors"]["S1"] == "Something went wrong"
    assert res["executed_slots"] == ["S1", "S2"]

def test_reentrancy_guard():
    bus = GoldenStackBus(register_defaults=False)
    
    def reentrant_handler(ev, pl, ctx):
        return bus.dispatch("NestedEvent")
        
    bus.register_slot("S1", 10, "slot1", reentrant_handler)
    
    res = bus.dispatch("OuterEvent")
    assert res["ok"] is True
    
    # Outer request goes through, inner request gets short-circuited
    # Since outer returns what inner returned, let's see inner's return
    assert res["reentrant_short_circuit"] is False
    assert res["executed_slots"] == ["S1"]
    
def test_explicit_golden_bus_active():
    bus = GoldenStackBus(register_defaults=False)
    res = bus.dispatch("TestEvent", {"_golden_bus_active": True})
    assert res["ok"] is True
    assert res["reentrant_short_circuit"] is True
    assert res["executed_slots"] == []

def test_telemetry_summary():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.dispatch("Event1")
    bus.dispatch("Event2")
    
    summary = bus.get_telemetry_summary()
    assert "S1" in summary
    assert summary["S1"]["count"] == 2
    assert summary["S1"]["allow_count"] == 2
    assert summary["S1"]["block_count"] == 0
    assert summary["S1"]["avg_ms"] > 0
    
    bus.reset_telemetry()
    summary = bus.get_telemetry_summary()
    assert summary["S1"]["count"] == 0
    assert summary["S1"]["allow_count"] == 0

def test_circuit_breaker():
    bus = GoldenStackBus(register_defaults=False)
    
    def failing_handler(ev, pl, ctx):
        raise ValueError("Error")
        
    bus.register_slot("S1", 10, "slot1", failing_handler)
    
    for _ in range(5):
        bus.dispatch("Event")
        
    cb = bus.get_circuit_breaker_health(window_size=10)
    assert cb["is_tripped"] is True
    assert cb["state"] == "OPEN"
    assert cb["failure_count"] == 5
    assert cb["total_recorded"] == 5
    
def test_compute_percentile_edge_cases():
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([1.0], 50) == 1.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 100) == 5.0

def test_merkle_tree_empty():
    assert _build_bus_merkle_tree([])["root"] == ""

def test_merkle_tree_single_leaf():
    leaf = b"test"
    tree = _build_bus_merkle_tree([leaf])
    import hashlib
    expected_root = hashlib.sha256(b"\x00" + leaf).hexdigest()
    assert tree["root"] == expected_root

def test_bus_merkle_digest():
    bus = GoldenStackBus(register_defaults=False)
    bus.register_slot("S1", 10, "slot1", lambda ev, pl, ctx: {"decision": "allow"})
    bus.dispatch("Ev1", {"k": "v1"})
    bus.dispatch("Ev2", {"k": "v2"})
    
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 2
    assert "merkle_root" in digest
    assert digest["merkle_root"] != ""
