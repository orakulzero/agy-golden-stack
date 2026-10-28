"""Tests for v1.2.0 GoldenStackBus SLA telemetry and station contract verification."""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Dict

import pytest

import agy_golden_stack
from agy_golden_stack import (
    GoldenStackBus,
    verify_v1_2_station_contracts,
)
from agy_golden_stack.slots import (
    slot_p30_iso9000_gate,
    slot_p50_oss_release_gate,
)


def test_telemetry_initial_state_empty(tmp_path: Path) -> None:
    """Verify newly initialized GoldenStackBus has empty telemetry summary for P10..P50."""
    bus = GoldenStackBus(workspace_root=tmp_path)
    summary = bus.get_telemetry_summary()

    for sid in ("P10", "P20", "P30", "P40", "P50"):
        assert sid in summary
        s = summary[sid]
        assert s["count"] == 0
        assert s["min_ms"] == 0.0
        assert s["avg_ms"] == 0.0
        assert s["p50_ms"] == 0.0
        assert s["p95_ms"] == 0.0
        assert s["max_ms"] == 0.0
        assert s["allow_count"] == 0
        assert s["block_count"] == 0


def test_telemetry_recording_and_summary_stats(tmp_path: Path) -> None:
    """Verify dispatch records elapsed durations and allow/block counts per slot."""
    bus = GoldenStackBus(workspace_root=tmp_path)

    # 1. Dispatch 3 allowed events
    for i in range(3):
        res = bus.dispatch("PreToolUse", {"tool_name": "view_file", "path": f"src/file_{i}.py"})
        assert res["decision"] == "allow"

    # 2. Dispatch 1 event blocked at P30
    res_block = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "write_file",
            "role": "implementer",
            "path": "tests/test_example.py",
        },
    )
    assert res_block["decision"] == "block"
    assert res_block["blocked_by"] == "P30"

    summary = bus.get_telemetry_summary()

    # P10 and P20 ran 4 times (3 allowed + 1 before block in P30)
    for sid in ("P10", "P20"):
        assert summary[sid]["count"] == 4
        assert summary[sid]["allow_count"] == 4
        assert summary[sid]["block_count"] == 0
        assert summary[sid]["min_ms"] <= summary[sid]["p50_ms"] <= summary[sid]["p95_ms"] <= summary[sid]["max_ms"]

    # P30 ran 4 times (3 allowed + 1 blocked)
    assert summary["P30"]["count"] == 4
    assert summary["P30"]["allow_count"] == 3
    assert summary["P30"]["block_count"] == 1

    # P40 and P50 did not execute during the 4th dispatch due to P30 block
    for sid in ("P40", "P50"):
        assert summary[sid]["count"] == 3
        assert summary[sid]["allow_count"] == 3
        assert summary[sid]["block_count"] == 0


def test_telemetry_reset(tmp_path: Path) -> None:
    """Verify reset_telemetry clears all recorded timings and counters back to empty state."""
    bus = GoldenStackBus(workspace_root=tmp_path)

    for _ in range(5):
        bus.dispatch("PreToolUse", {"tool_name": "view_file", "path": "src/module.py"})

    summary_before = bus.get_telemetry_summary()
    assert summary_before["P10"]["count"] == 5

    bus.reset_telemetry()
    summary_after = bus.get_telemetry_summary()

    for sid in ("P10", "P20", "P30", "P40", "P50"):
        assert summary_after[sid]["count"] == 0
        assert summary_after[sid]["min_ms"] == 0.0
        assert summary_after[sid]["avg_ms"] == 0.0
        assert summary_after[sid]["p50_ms"] == 0.0
        assert summary_after[sid]["p95_ms"] == 0.0
        assert summary_after[sid]["max_ms"] == 0.0
        assert summary_after[sid]["allow_count"] == 0
        assert summary_after[sid]["block_count"] == 0


def test_telemetry_custom_slot_registration(tmp_path: Path) -> None:
    """Verify custom slots register telemetry and calculate percentiles accurately."""
    bus = GoldenStackBus(workspace_root=tmp_path, register_defaults=False)
    bus.register_slot(
        slot_id="C01",
        priority=5,
        name="custom_slot",
        handler=lambda ev, pl, ctx: {"decision": "allow"},
    )

    for _ in range(20):
        bus.dispatch("CustomEvent", {"data": 123})

    summary = bus.get_telemetry_summary()
    assert "C01" in summary
    assert summary["C01"]["count"] == 20
    assert summary["C01"]["allow_count"] == 20
    assert summary["C01"]["block_count"] == 0
    assert summary["C01"]["p50_ms"] >= summary["C01"]["min_ms"]
    assert summary["C01"]["p95_ms"] >= summary["C01"]["p50_ms"]


def test_benchmark_1000_dispatches_with_active_telemetry(tmp_path: Path) -> None:
    """Verify <1.0 ms average dispatch latency across 1000 dispatches with active telemetry."""
    bus = GoldenStackBus(workspace_root=tmp_path)
    payload = {"tool_name": "view_file", "path": "src/agy_golden_stack/bus.py"}

    # Warmup
    for _ in range(50):
        bus.dispatch("PreToolUse", payload)

    bus.reset_telemetry()

    iterations = 1000
    t_start = time.perf_counter()
    for _ in range(iterations):
        res = bus.dispatch("PreToolUse", payload)
        assert res["decision"] == "allow"
    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    avg_latency_ms = total_elapsed_ms / iterations

    summary = bus.get_telemetry_summary()
    assert summary["P10"]["count"] == iterations
    assert summary["P50"]["count"] == iterations
    assert avg_latency_ms < 1.0, f"Average dispatch latency {avg_latency_ms:.4f} ms exceeded 1.0 ms"
    assert summary["P50"]["p95_ms"] < 1.0


def test_station_contracts_pe_reversing_lab_valid() -> None:
    """Verify valid pe_reversing_lab syscall_stubs payloads pass verification."""
    # Standard format with name, syscall_id, is_hooked
    p1 = {
        "syscall_stubs": [
            {"name": "NtAllocateVirtualMemory", "syscall_id": 24, "is_hooked": False},
            {"name": "NtProtectVirtualMemory", "syscall_id": 80, "is_hooked": True},
        ]
    }
    r1 = verify_v1_2_station_contracts(p1)
    assert r1["valid"] is True
    assert r1["checked_stations"] == ["pe_reversing_lab"]
    assert len(r1["violations"]) == 0

    # Alternative aliases: symbol, ssn, hooked under pe_reversing_lab dict
    p2 = {
        "pe_reversing_lab": {
            "syscall_stubs": [
                {"symbol": "NtCreateThreadEx", "ssn": 180, "hooked": False},
                {"ordinal": 12, "syscall_id": 181, "is_hooked": False},
            ]
        }
    }
    r2 = verify_v1_2_station_contracts(p2)
    assert r2["valid"] is True
    assert r2["checked_stations"] == ["pe_reversing_lab"]


def test_station_contracts_pe_reversing_lab_violations() -> None:
    """Verify malformed pe_reversing_lab payloads produce structured violations."""
    # Non-list stubs
    r1 = verify_v1_2_station_contracts({"syscall_stubs": "not-a-list"})
    assert r1["valid"] is False
    assert any("must be a list" in v for v in r1["violations"])

    # Item missing required fields
    r2 = verify_v1_2_station_contracts({
        "syscall_stubs": [{"raw_data": 123}]
    })
    assert r2["valid"] is False
    assert any("missing name" in v for v in r2["violations"])
    assert any("missing syscall_id" in v for v in r2["violations"])
    assert any("missing is_hooked" in v for v in r2["violations"])

    # Missing syscall_stubs key inside pe_reversing_lab dict
    r3 = verify_v1_2_station_contracts({"pe_reversing_lab": {}})
    assert r3["valid"] is False
    assert any("missing required 'syscall_stubs'" in v for v in r3["violations"])


def test_station_contracts_eskd_vision_station_valid() -> None:
    """Verify valid eskd_vision_station schemas pass verification."""
    payload = {
        "eskd_vision_station": {
            "gost_2308": [
                {"characteristic": "perpendicularity", "tolerance": 0.05, "datums": ["A"]},
                {"characteristic": "flatness", "tolerance": 0.02},
            ],
            "gost_2309": {"ra": 1.6, "value": 1.6},
            "gost_2316": {
                "items": ["1. Material: Steel 45.", "2. Hardness: HRC 40..45."],
                "tech_req_bbox": [0.5, 0.7, 0.4, 0.2],
            },
        }
    }
    res = verify_v1_2_station_contracts(payload)
    assert res["valid"] is True
    assert res["checked_stations"] == ["eskd_vision_station"]
    assert len(res["violations"]) == 0


def test_station_contracts_eskd_vision_station_violations() -> None:
    """Verify invalid eskd_vision_station schemas are detected."""
    # Negative tolerance in gost_2308
    r1 = verify_v1_2_station_contracts({
        "gost_2308": [{"characteristic": "flatness", "tolerance": -0.05}]
    })
    assert r1["valid"] is False
    assert any("tolerance must be positive" in v for v in r1["violations"])

    # Negative roughness in gost_2309
    r2 = verify_v1_2_station_contracts({
        "gost_2309": {"parameter": "Ra", "value": -1.0}
    })
    assert r2["valid"] is False
    assert any("missing positive roughness" in v for v in r2["violations"])

    # Malformed bbox in gost_2316
    r3 = verify_v1_2_station_contracts({
        "gost_2316": {"tech_req_bbox": [0.1, 0.2]}  # not 4 elements
    })
    assert r3["valid"] is False
    assert any("tech_req_bbox must be 4 coordinates" in v for v in r3["violations"])


def test_station_contracts_agy_secret_shield_valid_and_violations() -> None:
    """Verify agy_secret_shield obfuscated_findings validation and error detection."""
    valid_payload = {
        "obfuscated_findings": [
            {
                "encoding_type": "base64",
                "decode_depth": 1,
                "rule_id": "google_api_key",
                "redacted_tag": "[REDACTED_OBFUSCATED_DPAPI:a1b2c3d4e5f6]",
            },
            {
                "encoding_type": "hex",
                "decode_depth": 2,
                "rule_id": "openai_secret",
                "redacted_tag": "[REDACTED_OBFUSCATED_DPAPI:f6e5d4c3b2a1]",
            },
        ]
    }
    r_ok = verify_v1_2_station_contracts(valid_payload)
    assert r_ok["valid"] is True
    assert r_ok["checked_stations"] == ["agy_secret_shield"]

    # Decode depth < 1 violation
    r_bad = verify_v1_2_station_contracts({
        "obfuscated_findings": [
            {
                "encoding_type": "base64",
                "decode_depth": 0,
                "rule_id": "test",
                "redacted_tag": "[TAG]",
            }
        ]
    })
    assert r_bad["valid"] is False
    assert any("decode_depth must be integer >= 1" in v for v in r_bad["violations"])


def test_station_contracts_agy_federation_mesh_valid_and_violations() -> None:
    """Verify agy_federation_mesh retry_history and load_balancer contracts."""
    valid_payload = {
        "agy_federation_mesh": {
            "retry_history": [
                {"attempt_count": 0, "status": "failed"},
                {"attempt_count": 1, "status": "success"},
            ],
            "load_balancer": {
                "station_id": "secret_shield",
                "latency_ema_ms": 12.5,
                "weight": 1.0,
                "status": "ONLINE",
            },
        }
    }
    r_ok = verify_v1_2_station_contracts(valid_payload)
    assert r_ok["valid"] is True
    assert r_ok["checked_stations"] == ["agy_federation_mesh"]

    # Negative attempt_count violation
    r_bad = verify_v1_2_station_contracts({
        "retry_history": [{"attempt_count": -2}]
    })
    assert r_bad["valid"] is False
    assert any("non-negative integer attempt_count" in v for v in r_bad["violations"])


def test_station_contracts_multi_station_payload() -> None:
    """Verify composite multi-station payload validates across all 4 stations simultaneously."""
    composite = {
        "syscall_stubs": [
            {"name": "NtOpenProcess", "syscall_id": 38, "is_hooked": False}
        ],
        "gost_2308": [
            {"characteristic": "circularity", "tolerance": 0.01}
        ],
        "obfuscated_findings": [
            {
                "encoding_type": "base64url",
                "decode_depth": 1,
                "rule_id": "gh_token",
                "redacted_tag": "[REDACTED_OBFUSCATED_DPAPI:112233445566]",
            }
        ],
        "retry_history": [
            {"attempt_count": 0}
        ],
    }
    res = verify_v1_2_station_contracts(composite)
    assert res["valid"] is True
    assert res["checked_stations"] == [
        "agy_federation_mesh",
        "agy_secret_shield",
        "eskd_vision_station",
        "pe_reversing_lab",
    ]
    assert len(res["violations"]) == 0


def test_slot_p30_station_contracts_integration(tmp_path: Path) -> None:
    """Verify slot_p30 blocks on station contract violations under implementer role."""
    bus = GoldenStackBus(workspace_root=tmp_path)

    # 1. Implementer role with invalid station data -> BLOCKED
    res_block = bus.dispatch(
        "PreToolUse",
        {
            "role": "implementer",
            "tool_name": "view_file",
            "syscall_stubs": [{"broken": "missing fields"}],
        },
    )
    assert res_block["decision"] == "block"
    assert res_block["blocked_by"] == "P30"
    assert "Station contract violation" in res_block["reason"]

    # 2. Implementer role with valid station data -> ALLOWED
    res_allow = bus.dispatch(
        "PreToolUse",
        {
            "role": "implementer",
            "tool_name": "view_file",
            "syscall_stubs": [{"name": "NtClose", "syscall_id": 15, "is_hooked": False}],
        },
    )
    assert res_allow["decision"] == "allow"
    assert "station_contracts_verification" in res_allow["context"]
    assert res_allow["context"]["station_contracts_verification"]["valid"] is True


def test_slot_p50_station_contracts_release_gate_integration(tmp_path: Path) -> None:
    """Verify slot_p50 blocks git push/release when station contracts are violated."""
    # Write valid MIT license to pass baseline OSS gate
    (tmp_path / "LICENSE").write_text("MIT License\nCopyright (c) 2026\n", encoding="utf-8")

    bus = GoldenStackBus(workspace_root=tmp_path)

    # 1. git push with broken station contracts -> BLOCKED
    res_block = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "run_command",
            "command": "git push origin main",
            "syscall_stubs": [{"invalid": "entry"}],
        },
    )
    assert res_block["decision"] == "block"
    assert res_block["blocked_by"] == "P50"
    assert "Station contract violation in release gate" in res_block["reason"]

    # 2. git push with valid station contracts -> ALLOWED
    res_allow = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "run_command",
            "command": "git push origin main",
            "syscall_stubs": [{"name": "NtQuerySystemInformation", "syscall_id": 54, "is_hooked": False}],
        },
    )
    assert res_allow["decision"] == "allow"


def test_version_and_top_level_exports() -> None:
    """Verify package version is 1.2.0 and verify_v1_2_station_contracts is exported."""
    assert agy_golden_stack.__version__ in ("1.2.0", "2.0.0")
    assert callable(agy_golden_stack.verify_v1_2_station_contracts)


def test_pe_reversing_lab_rejects_negative_and_non_integer_syscall_ids() -> None:
    """Verify negative and non-integer syscall IDs are rejected."""
    bad_ids = [-1, -999, "invalid_ssn", 3.1415, True, False, None]
    for bad_id in bad_ids:
        payload = {
            "pe_reversing_lab": {
                "syscall_stubs": [{"name": "NtTest", "syscall_id": bad_id, "is_hooked": False}]
            }
        }
        res = verify_v1_2_station_contracts(payload)
        assert res["valid"] is False
        assert any("syscall_id/ssn must be non-negative integer" in v or "missing syscall_id or ssn" in v for v in res["violations"])


def test_pe_reversing_lab_rejects_non_boolean_hook_flags() -> None:
    """Verify non-boolean hook flags are rejected."""
    bad_hooks = ["not_a_bool", 12345, 0, 1, 3.14, ["nested"], {"a": 1}]
    for bad_hook in bad_hooks:
        payload = {
            "pe_reversing_lab": {
                "syscall_stubs": [{"name": "NtTest", "syscall_id": 10, "is_hooked": bad_hook}]
            }
        }
        res = verify_v1_2_station_contracts(payload)
        assert res["valid"] is False
        assert any("is_hooked/hooked must be a boolean" in v for v in res["violations"])


def test_agy_federation_mesh_rejects_negative_and_non_numeric_delays() -> None:
    """Verify negative and non-numeric delays in retry history are rejected."""
    bad_delays = ["invalid_str_delay", -10.0, -999, "NaN", None, True, False, float("nan")]
    for bad_delay in bad_delays:
        res = verify_v1_2_station_contracts({
            "retry_history": [{"attempt_count": 1, "delay_ms": bad_delay}]
        })
        assert res["valid"] is False
        assert any("delay must be non-negative number" in v for v in res["violations"])


def test_agy_federation_mesh_accepts_attempt_field_and_real_provenance() -> None:
    """Verify retry items with 'attempt' key and real federation mesh provenance are accepted."""
    # 1. Direct retry_history with 'attempt' instead of 'attempt_count'
    payload1 = {
        "retry_history": [
            {"attempt": 0, "status": "retry_1", "delay_ms": 1.5},
            {"attempt": 1, "status": "success", "delay_ms": 0.0},
        ]
    }
    r1 = verify_v1_2_station_contracts(payload1)
    assert r1["valid"] is True
    assert r1["checked_stations"] == ["agy_federation_mesh"]
    assert len(r1["violations"]) == 0

    # 2. Real agy-federation-mesh provenance activity record
    real_prov_activity = {
        "agy_federation_mesh": {
            "event": "prov:Activity",
            "task_id": "task_reversing_scan",
            "station_id": "pe_reversing_lab",
            "action": "scan",
            "attempt_count": 2,
            "retry_history": [
                {
                    "attempt": 1,
                    "error": "Transient connection reset",
                    "delay_ms": 1.43,
                    "timestamp": "2026-10-25T12:00:00Z",
                }
            ],
        }
    }
    r2 = verify_v1_2_station_contracts(real_prov_activity)
    assert r2["valid"] is True
    assert r2["checked_stations"] == ["agy_federation_mesh"]
    assert len(r2["violations"]) == 0


def test_slot_p30_and_p50_enforce_remediated_station_rules(tmp_path: Path) -> None:
    """Verify P30 blocks negative syscall IDs and P50 blocks corrupted delays."""
    (tmp_path / "LICENSE").write_text("MIT License\nCopyright (c) 2026\n", encoding="utf-8")
    bus = GoldenStackBus(workspace_root=tmp_path)

    # 1. P30 blocks negative syscall_id under implementer role
    res_p30_bad = bus.dispatch(
        "PreToolUse",
        {
            "role": "implementer",
            "tool_name": "view_file",
            "pe_reversing_lab": {
                "syscall_stubs": [{"name": "NtBad", "syscall_id": -999, "is_hooked": False}]
            },
        },
    )
    assert res_p30_bad["decision"] == "block"
    assert res_p30_bad["blocked_by"] == "P30"
    assert "syscall_id/ssn must be non-negative integer" in res_p30_bad["reason"]

    # 2. P30 allows real federation mesh payload
    res_p30_good = bus.dispatch(
        "PreToolUse",
        {
            "role": "implementer",
            "tool_name": "view_file",
            "agy_federation_mesh": {
                "attempt_count": 1,
                "retry_history": [{"attempt": 1, "delay_ms": 5.0}],
            },
        },
    )
    assert res_p30_good["decision"] == "allow"

    # 3. P50 blocks corrupted delay in git push
    res_p50_bad = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "run_command",
            "command": "git push origin main",
            "agy_federation_mesh": {
                "retry_history": [{"attempt_count": 1, "delay_ms": -500.0}],
            },
        },
    )
    assert res_p50_bad["decision"] == "block"
    assert res_p50_bad["blocked_by"] == "P50"
    assert "delay must be non-negative number" in res_p50_bad["reason"]
