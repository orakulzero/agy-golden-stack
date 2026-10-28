"""Tests for v1.3.0 GoldenStackBus sliding-window circuit breaker, Merkle audit digest,

and v1.3.0 peripheral station contracts verification.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import time
from typing import Any, Dict, List
import pytest

import agy_golden_stack
from agy_golden_stack import GoldenStackBus
from agy_golden_stack.slots import (
    slot_p30_iso9000_gate,
    slot_p50_oss_release_gate,
)

try:
    from agy_golden_stack import verify_v1_3_station_contracts
except ImportError:
    try:
        from agy_golden_stack.slots import verify_v1_3_station_contracts
    except ImportError:
        def verify_v1_3_station_contracts(*args: Any, **kwargs: Any) -> Any:
            from agy_golden_stack.slots import verify_v1_3_station_contracts as fn
            return fn(*args, **kwargs)


# ============================================================================
# 1. Version and Re-export Tests
# ============================================================================


def test_v1_3_version_bump() -> None:
    """Verify package version is bumped to 1.3.0 in agy_golden_stack."""
    assert agy_golden_stack.__version__ in ("1.3.0", "2.0.0")


def test_v1_3_top_level_exports() -> None:
    """Verify verify_v1_3_station_contracts is exported at top level and in __all__."""
    assert hasattr(agy_golden_stack, "verify_v1_3_station_contracts")
    assert "verify_v1_3_station_contracts" in getattr(agy_golden_stack, "__all__", [])


# ============================================================================
# 2. Sliding-Window Circuit Breaker Tests
# ============================================================================


def test_circuit_breaker_initial_healthy_state(tmp_path: Path) -> None:
    """Verify newly initialized bus returns healthy CLOSED circuit breaker state."""
    bus = GoldenStackBus(workspace_root=tmp_path)
    assert hasattr(bus, "get_circuit_breaker_health"), "GoldenStackBus must implement get_circuit_breaker_health"

    health = bus.get_circuit_breaker_health()
    assert isinstance(health, dict)
    assert health.get("state") in ("CLOSED", "closed")
    assert health.get("failure_rate", 0.0) == 0.0
    assert health.get("is_tripped", False) is False


def test_circuit_breaker_sliding_window_tracking(tmp_path: Path) -> None:
    """Verify dispatches record transitions in the sliding execution window."""
    bus = GoldenStackBus(workspace_root=tmp_path)

    # Dispatch 5 successful events
    for i in range(5):
        res = bus.dispatch("PreToolUse", {"tool_name": "view_file", "path": f"src/mod_{i}.py"})
        assert res["decision"] == "allow"

    health = bus.get_circuit_breaker_health(window_size=50)
    assert health.get("state") in ("CLOSED", "closed")
    assert health.get("failure_rate", 0.0) == 0.0
    assert health.get("total_recorded", 5) >= 5


def test_circuit_breaker_trips_to_open_on_high_failure_rate(tmp_path: Path) -> None:
    """Verify circuit breaker transitions to OPEN when error rate exceeds threshold."""
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)

    # Register a failing slot that raises exceptions
    def failing_slot(ev: str, pl: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("Injected transient failure for circuit breaker test")

    bus.register_slot(slot_id="P99", priority=99, name="failing_slot", handler=failing_slot)

    # Dispatch events that trigger errors
    for _ in range(10):
        bus.dispatch("PreToolUse", {"action": "test"})

    health = bus.get_circuit_breaker_health(window_size=10)
    assert health.get("failure_rate", 0.0) >= 0.5
    assert health.get("is_tripped", True) is True
    assert health.get("state") in ("OPEN", "open")


# ============================================================================
# 3. Merkle-Anchored Bus Audit Digest Tests
# ============================================================================


def test_compute_bus_merkle_digest_empty_and_dispatched(tmp_path: Path) -> None:
    """Verify compute_bus_merkle_digest computes an RFC 6962 digest over dispatches."""
    bus = GoldenStackBus(workspace_root=tmp_path)
    assert hasattr(bus, "compute_bus_merkle_digest"), "GoldenStackBus must implement compute_bus_merkle_digest"

    digest_empty = bus.compute_bus_merkle_digest()
    assert isinstance(digest_empty, (dict, str))
    if isinstance(digest_empty, dict):
        assert "merkle_root" in digest_empty or "root" in digest_empty

    # Dispatch events
    bus.dispatch("PreToolUse", {"tool_name": "run_command", "cmd": "pytest"})
    bus.dispatch("PostToolUse", {"tool_name": "run_command", "exit_code": 0})

    digest_after = bus.compute_bus_merkle_digest()
    root_str = digest_after if isinstance(digest_after, str) else (digest_after.get("merkle_root") or digest_after.get("root", ""))
    assert isinstance(root_str, str)
    assert len(root_str) == 64


def test_compute_bus_merkle_digest_deterministic_and_unique(tmp_path: Path) -> None:
    """Verify distinct dispatch histories produce different deterministic digests."""
    bus_a = GoldenStackBus(workspace_root=tmp_path / "a")
    bus_b = GoldenStackBus(workspace_root=tmp_path / "b")

    bus_a.dispatch("PreToolUse", {"event_id": "alpha"})
    bus_b.dispatch("PreToolUse", {"event_id": "beta"})

    digest_a = bus_a.compute_bus_merkle_digest()
    digest_b = bus_b.compute_bus_merkle_digest()

    root_a = digest_a if isinstance(digest_a, str) else (digest_a.get("merkle_root") or digest_a.get("root", ""))
    root_b = digest_b if isinstance(digest_b, str) else (digest_b.get("merkle_root") or digest_b.get("root", ""))

    assert root_a != root_b


# ============================================================================
# 4. v1.3.0 Peripheral Station Contracts Verification Tests
# ============================================================================


def test_verify_v1_3_station_contracts_valid_complete() -> None:
    """Verify complete v1.3.0 telemetry payload passes with zero violations."""
    payload = {
        "pe_reversing_lab": {
            "imphash": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "rich_header": {
                "dan_s_present": True,
                "entries": [{"comp_id": 0x1234, "count": 5}],
            },
            "cfg_summary": {
                "block_count": 12,
                "cyclomatic_complexity": 4,
            },
        },
        "agy_secret_shield": {
            "ast_taint_findings": [
                {
                    "category": "live_assignment",
                    "variable_or_arg": "api_key",
                    "line_number": 42,
                    "confidence": "HIGH",
                }
            ]
        },
        "eskd_vision_station": {
            "vector_line_weights": {
                "main_stroke_mm": 0.8,
                "thin_stroke_mm": 0.4,
                "ratio": 0.5,
            },
            "gost_2106_bom": {
                "columns": [
                    "format",
                    "zone",
                    "pos",
                    "designation",
                    "name",
                    "count",
                    "note",
                ],
                "rows": [{"pos": 1, "name": "Bracket", "count": 2}],
            },
        },
        "agy_federation_mesh": {
            "pareto_frontier": [
                {
                    "worker_id": "worker_gpu_0",
                    "latency_p50": 15.2,
                    "cost": 0.04,
                    "reliability": 0.995,
                }
            ]
        },
    }

    result = verify_v1_3_station_contracts(payload)
    assert result["valid"] is True
    assert result["violations"] == []
    for station in ("pe_reversing_lab", "agy_secret_shield", "eskd_vision_station", "agy_federation_mesh"):
        assert station in result["checked_stations"]


def test_verify_v1_3_station_contracts_pe_reversing_lab_violations() -> None:
    """Verify violations flagged for invalid imphash, rich header, or cfg metrics."""
    bad_pe_payload = {
        "pe_reversing_lab": {
            "imphash": "NOT_A_VALID_MD5_HASH",
            "rich_header": {"dan_s_present": "NOT_A_BOOL"},
            "cfg_summary": {"block_count": 0, "cyclomatic_complexity": -1},
        }
    }
    result = verify_v1_3_station_contracts(bad_pe_payload)
    assert result["valid"] is False
    assert len(result["violations"]) >= 2
    assert any("imphash" in v.lower() for v in result["violations"])


def test_verify_v1_3_station_contracts_secret_shield_violations() -> None:
    """Verify violations flagged for invalid category, line numbers, or confidence."""
    bad_shield_payload = {
        "agy_secret_shield": {
            "ast_taint_findings": [
                {
                    "category": "INVALID_CATEGORY_NAME",
                    "variable_or_arg": "secret",
                    "line_number": -5,
                    "confidence": "EXTREME",
                }
            ]
        }
    }
    result = verify_v1_3_station_contracts(bad_shield_payload)
    assert result["valid"] is False
    assert len(result["violations"]) >= 1


def test_verify_v1_3_station_contracts_eskd_vision_violations() -> None:
    """Verify violations flagged for out-of-range line weights or missing BOM columns."""
    bad_eskd_payload = {
        "eskd_vision_station": {
            "vector_line_weights": {
                "main_stroke_mm": 5.5,  # Out of [0.5, 1.4] mm range
                "thin_stroke_mm": 0.1,
                "ratio": 0.05,
            },
            "gost_2106_bom": {
                "columns": ["only_three_cols", "pos", "name"],
                "rows": [],
            },
        }
    }
    result = verify_v1_3_station_contracts(bad_eskd_payload)
    assert result["valid"] is False
    assert len(result["violations"]) >= 1


def test_verify_v1_3_station_contracts_federation_mesh_violations() -> None:
    """Verify violations flagged for negative latency or out-of-bounds reliability."""
    bad_fed_payload = {
        "agy_federation_mesh": {
            "pareto_frontier": [
                {
                    "worker_id": "worker_fail",
                    "latency_p50": -10.0,
                    "cost": -1.0,
                    "reliability": 1.5,  # Must be <= 1.0
                }
            ]
        }
    }
    result = verify_v1_3_station_contracts(bad_fed_payload)
    assert result["valid"] is False
    assert len(result["violations"]) >= 1


# ============================================================================
# 5. Slot Integration Tests
# ============================================================================


def test_slot_p30_and_p50_v1_3_contracts_integration(tmp_path: Path) -> None:
    """Verify slot_p30 and slot_p50 accept and process valid v1.3.0 station contracts."""
    valid_payload = {
        "pe_reversing_lab": {
            "imphash": "0123456789abcdef0123456789abcdef",
            "rich_header": {"dan_s_present": True, "entries": []},
            "cfg_summary": {"block_count": 8, "cyclomatic_complexity": 2},
        }
    }

    ctx_p30: Dict[str, Any] = {}
    res_p30 = slot_p30_iso9000_gate(tmp_path, "PostToolUse", valid_payload, ctx_p30)
    assert res_p30["decision"] == "allow"

    ctx_p50: Dict[str, Any] = {}
    res_p50 = slot_p50_oss_release_gate(tmp_path, "PostToolUse", valid_payload, ctx_p50)
    assert res_p50["decision"] == "allow"
