import pytest
from pathlib import Path
from agy_golden_stack.bus import GoldenStackBus

def test_reentrancy_active_depth(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    # We will register a slot that dispatches another event.
    inner_results = []
    
    def reentrant_handler(ev, pl, ctx):
        # Dispatch a nested event
        res = bus.dispatch("NestedEvent")
        inner_results.append(res)
        return {"decision": "allow"}

    bus.register_slot("P10", 10, "reentrant_slot", reentrant_handler)
    
    res = bus.dispatch("OuterEvent")
    
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "P10" in res["executed_slots"]
    
    # Check inner dispatch result
    assert len(inner_results) == 1
    inner_res = inner_results[0]
    assert inner_res["reentrant_short_circuit"] is True
    assert inner_res["event"] == "NestedEvent"
    assert inner_res["total_duration_ms"] == 0.0
    assert inner_res["executed_slots"] == []

def test_reentrancy_payload_flag(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    res = bus.dispatch("AnyEvent", {"_golden_bus_active": True})
    
    assert res["reentrant_short_circuit"] is True
    assert res["ok"] is True
    assert res["executed_slots"] == []

def test_slot_handler_error(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    def error_handler(ev, pl, ctx):
        raise ValueError("Something went wrong")

    bus.register_slot("P10", 10, "error_slot", error_handler)
    
    res = bus.dispatch("ErrorEvent")
    
    # Should not blow up but return allow, and log error
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "P10" in res["slot_errors"]
    assert res["slot_errors"]["P10"] == "Something went wrong"

def test_empty_merkle_digest(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    res = bus.compute_bus_merkle_digest()
    assert res["merkle_root"] == ""
    assert res["entry_count"] == 0

def test_circuit_breaker_empty(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    
    res = bus.get_circuit_breaker_health()
    assert res["state"] == "CLOSED"
    assert res["is_tripped"] is False
    assert res["failure_count"] == 0

def test_merkle_digest_with_events(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    bus.register_slot("P10", 10, "dummy", lambda e, p, c: {"decision": "allow"})
    
    bus.dispatch("Ev1", {"k": "v"})
    bus.dispatch("Ev2")
    
    res = bus.compute_bus_merkle_digest()
    assert res["entry_count"] == 2
    assert res["merkle_root"] != ""
    assert len(res["tree"]["levels"]) > 0
