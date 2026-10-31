import pytest
from pathlib import Path
import time
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration, _compute_percentile, _build_bus_merkle_tree
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

def test_req001_default_slots_and_priority_order(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    slot_ids = [slot.slot_id for slot in bus.slots]
    assert slot_ids == ["P10", "P20", "P30", "P40", "P50"]

    res = bus.dispatch("SessionStart", {"prompt": "hello world"})
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert res["executed_slots"] == ["P10", "P20", "P30", "P40", "P50"]

def test_bus_reentrancy(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    
    reentrant_dispatch = bus.dispatch("TestEvent", {"_golden_bus_active": True})
    assert reentrant_dispatch["reentrant_short_circuit"] is True
    
    # Try actual nested dispatch
    def reentrant_handler(ev, pl, ctx):
        inner_res = bus.dispatch("InnerEvent", {})
        assert inner_res["reentrant_short_circuit"] is True
        return {"decision": "allow"}

    bus.register_slot("P60", 60, "reentrant_test", reentrant_handler)
    res = bus.dispatch("OuterEvent", {})
    assert res["ok"] is True
    assert "P60" in res["executed_slots"]

def test_circuit_breaker(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    
    def failing_handler(ev, pl, ctx):
        raise Exception("Handler failed")

    bus.register_slot("P60", 60, "fail_test", failing_handler)
    
    for _ in range(5):
        bus.dispatch("FailEvent", {})
        
    health = bus.get_circuit_breaker_health(window_size=5)
    assert health["state"] == "OPEN"
    assert health["is_tripped"] is True
    assert health["failure_count"] == 5
    
    def passing_handler(ev, pl, ctx):
        return {"decision": "allow"}
        
    bus.register_slot("P60", 60, "pass_test", passing_handler)
    for _ in range(5):
        bus.dispatch("PassEvent", {})
        
    health = bus.get_circuit_breaker_health(window_size=10)
    assert health["state"] == "OPEN" # Still >= 0.5 failure rate (5 fails out of 10)
    
    for _ in range(1):
        bus.dispatch("PassEvent", {})
        
    health = bus.get_circuit_breaker_health(window_size=10)
    assert health["state"] == "CLOSED" # Failure rate < 0.5 (4 fails, 6 successes)

def test_merkle_digest(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path, register_defaults=False)
    
    digest_empty = bus.compute_bus_merkle_digest()
    assert digest_empty["entry_count"] == 0
    assert digest_empty["merkle_root"] == ""
    
    bus.dispatch("Event1", {"key": "val1"})
    digest1 = bus.compute_bus_merkle_digest()
    assert digest1["entry_count"] == 1
    root1 = digest1["merkle_root"]
    
    bus.dispatch("Event2", {"key": "val2"})
    digest2 = bus.compute_bus_merkle_digest()
    assert digest2["entry_count"] == 2
    root2 = digest2["merkle_root"]
    
    assert root1 != root2
    assert len(digest2["tree"]["levels"]) > 1

def test_telemetry(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path, register_defaults=False)
    
    def slow_handler(ev, pl, ctx):
        time.sleep(0.01)
        return {"decision": "allow"}

    bus.register_slot("P10", 10, "slow", slow_handler)
    bus.dispatch("TestEvent", {})
    
    summary = bus.get_telemetry_summary()
    assert "P10" in summary
    assert summary["P10"]["count"] == 1
    assert summary["P10"]["avg_ms"] > 0
    
    bus.reset_telemetry()
    summary2 = bus.get_telemetry_summary()
    assert summary2["P10"]["count"] == 0

def test_computer_use_interceptor(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path, register_defaults=False)
    
    # inspect_computer_use_bus_event is mocked to return {"allowed": True}
    # We can just verify it gets called and doesn't block by default
    res = bus.dispatch("ComputerUseAction", {})
    assert res["ok"] is True
    assert "cua_safety_inspection" in res["context"]
    assert res["context"]["cua_safety_inspection"]["allowed"] is True

def test_compute_percentile():
    assert _compute_percentile([], 50) == 0.0
    assert _compute_percentile([1.0], 50) == 1.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 100) == 5.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 0) == 1.0
    assert _compute_percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.5

def test_slot_blocking(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path, register_defaults=False)
    def block_handler(ev, pl, ctx):
        return {"decision": "block", "reason": "test block"}
    def allow_handler(ev, pl, ctx):
        return {"decision": "allow"}
    
    bus.register_slot("P10", 10, "block", block_handler)
    bus.register_slot("P20", 20, "allow", allow_handler)
    
    res = bus.dispatch("Test", {})
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P10"
    assert "P10" in res["executed_slots"]
    assert "P20" not in res["executed_slots"]
