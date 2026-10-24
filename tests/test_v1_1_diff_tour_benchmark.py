"""Tests for diff-tour v1 integration in GoldenStackBus P30/P50 and <1.0 ms latency benchmark."""

from __future__ import annotations

import json
from pathlib import Path
import time
import pytest

from agy_golden_stack.bus import GoldenStackBus
from iso9000_agentops.diff_tour import build_diff_tour


def test_slot_p30_diff_tour_validation_and_sanitization(tmp_path: Path) -> None:
    bus = GoldenStackBus(workspace_root=tmp_path)

    valid_tour = build_diff_tour(
        title="Bus P30 Tour",
        description="Verify review dimensions",
        steps=[
            {
                "file": "src/module.py",
                "line_start": 1,
                "line_end": 10,
                "dimension": "L1_PROMISES",
                "epistemic_basis": "fact",
                "description": "Valid first step.",
                "asks": ["Initial ask"],
            },
            {
                "file": "src/module.py",
                "line_start": 11,
                "line_end": 20,
                "dimension": "L2_FAILURE",
                "epistemic_basis": "inferred",
                "description": "Step before question.",
                "asks": ["Ask to be dropped"],
            },
            {
                "file": "src/module.py",
                "line_start": 21,
                "line_end": 30,
                "dimension": "L4_TRUST",
                "epistemic_basis": "opinion",
                "description": "Question step.",
                "question": True,
                "asks": ["Revealing question ask"],
            },
        ],
    )

    # 1. Dispatch valid tour
    res = bus.dispatch("PreToolUse", {"tool_name": "review", "diff_tour": valid_tour})
    assert res["decision"] == "allow"
    assert "diff_tour_validation" in res["context"]
    assert res["context"]["diff_tour_validation"]["valid"] is True
    sanitized = res["context"]["sanitized_diff_tour"]
    assert "asks" in sanitized["steps"][0]
    assert "asks" not in sanitized["steps"][1]
    assert "asks" not in sanitized["steps"][2]

    # 2. Dispatch invalid tour (invalid dimension & epistemic basis)
    invalid_tour = {
        "title": "Broken Tour",
        "steps": [
            {
                "file": "foo.py",
                "line_start": 1,
                "line_end": 5,
                "dimension": "INVALID_DIM",
                "epistemic_basis": "guess",
                "description": "Broken step",
            }
        ],
    }
    res_block = bus.dispatch("PreToolUse", {"tool_name": "review", "diff_tour": invalid_tour})
    assert res_block["decision"] == "block"
    assert res_block["blocked_by"] == "P30"
    assert "Diff-Tour validation failed" in res_block["reason"]


def test_slot_p50_diff_tour_file_audit(tmp_path: Path) -> None:
    # Setup dummy repo with MIT LICENSE
    lic_file = tmp_path / "LICENSE"
    lic_file.write_text("MIT License\nCopyright (c) 2026\n", encoding="utf-8")

    # Add an invalid tour file
    tour_file = tmp_path / "broken.tour.json"
    tour_file.write_text(json.dumps({
        "title": "Invalid On-Disk Tour",
        "steps": [{"file": "bar.py", "line_start": 1, "line_end": 5, "dimension": "BAD", "epistemic_basis": "fact", "description": "x"}]
    }), encoding="utf-8")

    bus = GoldenStackBus(workspace_root=tmp_path)
    res = bus.dispatch("PreToolUse", {"tool_name": "run_command", "command": "git push origin main"})
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P50"
    assert "Diff-Tour validation failed" in res["reason"]


def test_benchmark_1000_dispatches_sub_millisecond_latency(tmp_path: Path) -> None:
    """Requirement: <1.0 ms average in-process 5-slot dispatch latency across 1000 iterations."""
    bus = GoldenStackBus(workspace_root=tmp_path)
    payload = {"tool_name": "view_file", "path": "src/agy_golden_stack/bus.py"}

    # Warmup
    for _ in range(50):
        bus.dispatch("PreToolUse", payload)

    iterations = 1000
    t_start = time.perf_counter()
    for _ in range(iterations):
        res = bus.dispatch("PreToolUse", payload)
        assert res["decision"] == "allow"
    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    avg_latency_ms = total_elapsed_ms / iterations

    print(f"\n[BENCHMARK] 1000 dispatches total: {total_elapsed_ms:.2f} ms, avg: {avg_latency_ms:.4f} ms/dispatch")
    assert avg_latency_ms < 1.0, f"Average dispatch latency {avg_latency_ms:.4f} ms exceeded 1.0 ms threshold"
