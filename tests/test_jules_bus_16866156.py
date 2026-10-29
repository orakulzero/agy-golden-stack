import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest
from agy_golden_stack.bus import GoldenStackBus, SlotRegistration

def test_empty_event_name_dispatch_no_exception(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    
    # Empty event name, no payload
    res1 = bus.dispatch("")
    assert res1["ok"] is True
    assert res1["event"] == ""
    assert res1["reentrant_short_circuit"] is False
    
    # Empty event name, short-circuit active
    res2 = bus.dispatch("", {"_golden_bus_active": True})
    assert res2["ok"] is True
    assert res2["event"] == ""
    assert res2["reentrant_short_circuit"] is True
    assert res2["total_duration_ms"] == 0.0
    assert res2["decision"] == "allow"
    assert res2["blocked_by"] is None

def test_reentrancy_active_depth(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    
    # Simulate active depth > 0
    bus._active_depth = 1
    res = bus.dispatch("AnyEvent")
    assert res["reentrant_short_circuit"] is True
    assert res["event"] == "AnyEvent"

def test_computer_use_interceptor(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    # The interceptor allows by default in our mock `slots.py`
    res = bus.dispatch("ComputerUseAction", {})
    assert res["ok"] is True
    
    res2 = bus.dispatch("PreToolUse", {"tool_name": "cu_browser"})
    assert res2["ok"] is True

def test_telemetry_and_circuit_breaker(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    bus.dispatch("Event1")
    bus.dispatch("Event2")
    
    cb = bus.get_circuit_breaker_health()
    assert cb["state"] == "CLOSED"
    assert cb["failure_count"] == 0
    assert cb["total_recorded"] == 2
    
    summary = bus.get_telemetry_summary()
    assert "P10" in summary
    assert summary["P10"]["count"] == 2
    
    bus.reset_telemetry()
    summary2 = bus.get_telemetry_summary()
    assert summary2["P10"]["count"] == 0

def test_merkle_digest(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    bus.dispatch("Event1", {"a": 1})
    bus.dispatch("Event2", {"b": 2})
    
    digest = bus.compute_bus_merkle_digest()
    assert "merkle_root" in digest
    assert digest["entry_count"] == 2

def test_slot_exception_handling(tmp_path: Path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    
    def bad_handler(ev, pl, ctx):
        raise ValueError("Boom!")
    
    bus.register_slot("P60", 60, "bad_slot", bad_handler)
    res = bus.dispatch("TestEvent")
    assert res["ok"] is True
    assert "P60" in res["slot_errors"]
    assert "Boom!" in res["slot_errors"]["P60"]
    
    # A slot throwing exception is recorded as success=False in _record_dispatch
    cb = bus.get_circuit_breaker_health()
    assert cb["failure_count"] == 1
