import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from agy_golden_stack.bus import GoldenStackBus

def test_bus_active_payload_short_circuit(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch("SessionStart", {"_golden_bus_active": True})
    assert res["ok"] is True
    assert res["reentrant_short_circuit"] is True
    assert res["total_duration_ms"] == 0.0

def test_bus_active_depth_short_circuit(tmp_path):
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    bus._active_depth = 1
    res = bus.dispatch("SessionStart", {})
    assert res["ok"] is True
    assert res["reentrant_short_circuit"] is True
    assert res["total_duration_ms"] == 0.0
