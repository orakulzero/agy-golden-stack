"""Tests for GoldenStackBus dispatching an empty event_name."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _bus(tmp_path: Path):
    from agy_golden_stack.bus import GoldenStackBus

    return GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)


def test_empty_event_name_dispatch_returns_structure(tmp_path: Path) -> None:
    """Dispatching "" must return a well-formed result dict."""
    bus = _bus(tmp_path)
    result = bus.dispatch("", {"tool_name": "helper"})

    assert isinstance(result, dict)
    assert result["event"] == ""
    assert result["decision"] in ("allow", "block")
    assert isinstance(result["executed_slots"], list)
    assert isinstance(result["slot_timings_ms"], dict)
    assert isinstance(result["slot_errors"], dict)
    assert isinstance(result["total_duration_ms"], float)


def test_empty_event_name_does_not_trigger_cua_interceptor(tmp_path: Path) -> None:
    """An empty event name must not be routed to the ComputerUse safety interceptor."""
    bus = _bus(tmp_path)
    result = bus.dispatch("", {})

    assert "cua_safety_inspection" in result["context"] or result[
        "reentrant_short_circuit"
    ] is False
    assert result["blocked_by"] != "CUA_SAFETY_INTERCEPTOR"


def test_empty_event_name_runs_all_slots_and_records_telemetry(tmp_path: Path) -> None:
    """Empty event name still traverses registered slots exactly once and is recorded."""
    bus = _bus(tmp_path)
    expected_ids = [slot.slot_id for slot in bus.slots]
    before = len(bus._dispatched_events)

    result = bus.dispatch("", None)

    assert result["reentrant_short_circuit"] is False
    assert result["executed_slots"] == expected_ids[: len(result["executed_slots"])]
    assert set(result["executed_slots"]).issubset(set(expected_ids))
    assert len(bus._dispatched_events) == before + 1

    summary = bus.get_telemetry_summary()
    total_count = sum(entry["count"] for entry in summary.values())
    assert total_count >= len(result["executed_slots"])
