from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.bus import GoldenStackBus


def _allow(ev, pl, ctx):
    return {"decision": "allow"}


def _block(ev, pl, ctx):
    return {"decision": "block", "reason": "blocked"}


def _make_bus(tmp_path: Path) -> GoldenStackBus:
    return GoldenStackBus(
        workspace_root=tmp_path, config_root=tmp_path, register_defaults=False
    )


def test_dispatch_priority_order_and_allow(tmp_path: Path) -> None:
    bus = _make_bus(tmp_path)
    bus.register_slot("P30", 30, "c", _allow)
    bus.register_slot("P10", 10, "a", _allow)
    bus.register_slot("P20", 20, "b", _allow)
    assert [s.slot_id for s in bus.slots] == ["P10", "P20", "P30"]
    res = bus.dispatch("TestEvent", {"k": "v"})
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert res["executed_slots"] == ["P10", "P20", "P30"]
    assert res["blocked_by"] is None


def test_dispatch_blocks_and_stops_chain(tmp_path: Path) -> None:
    bus = _make_bus(tmp_path)
    bus.register_slot("P10", 10, "a", _allow)
    bus.register_slot("P20", 20, "b", _block)
    bus.register_slot("P30", 30, "c", _allow)
    res = bus.dispatch("TestEvent")
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P20"
    assert res["executed_slots"] == ["P10", "P20"]


def test_reentrancy_short_circuit(tmp_path: Path) -> None:
    bus = _make_bus(tmp_path)
    bus.register_slot("P10", 10, "a", _allow)
    res = bus.dispatch("TestEvent", {"_golden_bus_active": True})
    assert res["reentrant_short_circuit"] is True
    assert res["executed_slots"] == []


def test_telemetry_and_circuit_breaker(tmp_path: Path) -> None:
    bus = _make_bus(tmp_path)
    bus.register_slot("P10", 10, "a", _allow)
    bus.dispatch("E1")
    bus.dispatch("E2")
    summary = bus.get_telemetry_summary()
    assert summary["P10"]["count"] == 2
    assert summary["P10"]["allow_count"] == 2
    health = bus.get_circuit_breaker_health()
    assert health["state"] == "CLOSED"
    assert health["is_tripped"] is False
    bus.reset_telemetry()
    assert bus.get_telemetry_summary()["P10"]["count"] == 0


def test_merkle_digest_deterministic(tmp_path: Path) -> None:
    bus = _make_bus(tmp_path)
    bus.register_slot("P10", 10, "a", _allow)
    bus.dispatch("E1", {"x": 1})
    digest = bus.compute_bus_merkle_digest()
    assert digest["entry_count"] == 1
    assert len(digest["merkle_root"]) == 64
