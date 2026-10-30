import pytest
import time
from pathlib import Path
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration

@pytest.fixture
def temp_bus(tmp_path):
    return GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)

def test_initialization_default_slots(temp_bus):
    assert len(temp_bus.slots) == 5
    assert [s.slot_id for s in temp_bus.slots] == ["P10", "P20", "P30", "P40", "P50"]
    assert [s.priority for s in temp_bus.slots] == [10, 20, 30, 40, 50]

def test_register_custom_slot(temp_bus):
    def dummy_handler(ev, pl, ctx):
        return {"decision": "allow"}
    temp_bus.register_slot("P15", 15, "custom_slot", dummy_handler)
    assert len(temp_bus.slots) == 6
    assert [s.slot_id for s in temp_bus.slots] == ["P10", "P15", "P20", "P30", "P40", "P50"]

def test_dispatch_basic(temp_bus):
    res = temp_bus.dispatch("SomeEvent", {"data": 123})
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "P10" in res["executed_slots"]
    assert len(res["executed_slots"]) == 5

def test_dispatch_reentrant(temp_bus):
    res = temp_bus.dispatch("Event1", {"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True
    assert len(res["executed_slots"]) == 0

def test_dispatch_computer_use_blocked(temp_bus, monkeypatch):
    import agy_golden_stack.bus
    monkeypatch.setattr(agy_golden_stack.bus, "inspect_computer_use_bus_event", lambda ev, pl, ctx: {"allowed": False, "reason": "unsafe"})
    res = temp_bus.dispatch("ComputerUse", {"data": "test"})
    assert res["ok"] is False
    assert res["decision"] == "block"
    assert res["blocked_by"] == "CUA_SAFETY_INTERCEPTOR"

def test_dispatch_slot_exception(temp_bus):
    def error_handler(ev, pl, ctx):
        raise ValueError("Something broke")
    temp_bus.register_slot("P25", 25, "error_slot", error_handler)
    res = temp_bus.dispatch("TestEvent")
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "P25" in res["slot_errors"]
    assert res["slot_errors"]["P25"] == "Something broke"

def test_dispatch_slot_blocked(temp_bus):
    def block_handler(ev, pl, ctx):
        return {"decision": "block", "reason": "manual block"}
    temp_bus.register_slot("P15", 15, "blocker", block_handler)
    res = temp_bus.dispatch("BlockEvent")
    assert res["ok"] is True
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P15"
    assert "P20" not in res["executed_slots"]

def test_telemetry(temp_bus):
    temp_bus.dispatch("Ev1")
    temp_bus.dispatch("Ev2")
    summary = temp_bus.get_telemetry_summary()
    assert summary["P10"]["count"] == 2
    assert summary["P10"]["allow_count"] == 2
    
    temp_bus.reset_telemetry()
    summary = temp_bus.get_telemetry_summary()
    assert summary["P10"]["count"] == 0
    assert summary["P10"]["allow_count"] == 0

def test_circuit_breaker(temp_bus):
    def error_handler(ev, pl, ctx):
        raise ValueError("Ouch")
    temp_bus.register_slot("P15", 15, "error", error_handler)
    
    # Generate 5 success (handled errors count as success for circuit breaker, unless we simulate failures differently)
    # Wait, in the code:
    # is_error = len(slot_errors) > 0
    # self._execution_window.append({"success": not is_error ...})
    # So exceptions in slots trip the circuit breaker.
    for _ in range(5):
        temp_bus.dispatch("ErrEv")
    
    health = temp_bus.get_circuit_breaker_health(10)
    assert health["is_tripped"] is True
    assert health["state"] == "OPEN"

def test_merkle_digest(temp_bus):
    res1 = temp_bus.dispatch("Ev1", {"k": "v1"})
    res2 = temp_bus.dispatch("Ev2", {"k": "v2"})
    
    digest = temp_bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 2
    assert digest["root"] != ""
