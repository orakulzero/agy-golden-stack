"""Agile V Locked Test Suite for Uncle Bob ub-mode and Anti-Decoherence Guard.

REQ-GS-M3: Verifies UBModeCheckResult, UBModeGuard TDD sequencing,
AST duplicate abstraction detection, and GoldenStackBus P30 slot integration.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
import time
from typing import Any, Dict, List
import pytest

from agy_golden_stack.bus import GoldenStackBus
from agy_golden_stack.slots import slot_p30_iso9000_gate
from agy_golden_stack.ub_mode_guard import UBModeCheckResult, UBModeGuard


def test_ub_mode_check_result_dataclass_contract() -> None:
    res = UBModeCheckResult(is_compliant=True, rule_name="TDD_TEST_FIRST", violations=[])
    assert res.is_compliant is True
    assert res.rule_name == "TDD_TEST_FIRST"
    assert res.violations == []
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.is_compliant = False  # type: ignore[misc]

    res_fail = UBModeCheckResult(
        is_compliant=False, rule_name="NO_DUPLICATION", violations=["Duplicate abstraction"]
    )
    assert res_fail.is_compliant is False
    assert len(res_fail.violations) == 1


def test_ub_mode_guard_initialization() -> None:
    guard = UBModeGuard()
    assert isinstance(guard, UBModeGuard)


def test_verify_tdd_sequence_compliant_with_staged_tests() -> None:
    guard = UBModeGuard()
    res = guard.verify_tdd_sequence(
        modified_files=["src/agy_golden_stack/ub_mode_guard.py"],
        test_files=["tests/test_ub_mode_guard.py"],
    )
    assert res.is_compliant is True
    assert res.rule_name == "TDD_TEST_FIRST"
    assert res.violations == []


def test_verify_tdd_sequence_compliant_only_test_files() -> None:
    guard = UBModeGuard()
    res = guard.verify_tdd_sequence(modified_files=[], test_files=["tests/test_new_feature.py"])
    assert res.is_compliant is True
    assert res.violations == []


def test_verify_tdd_sequence_violation_when_production_code_lacks_tests() -> None:
    guard = UBModeGuard()
    res = guard.verify_tdd_sequence(
        modified_files=["src/agy_golden_stack/ub_mode_guard.py"],
        test_files=[],
    )
    assert res.is_compliant is False
    assert res.rule_name == "TDD_TEST_FIRST"
    assert len(res.violations) > 0
    assert any("test" in v.lower() or "tdd" in v.lower() for v in res.violations)


def test_verify_tdd_sequence_non_production_files_ignored() -> None:
    guard = UBModeGuard()
    res = guard.verify_tdd_sequence(
        modified_files=["README.md", "docs/architecture.md"],
        test_files=[],
    )
    assert res.is_compliant is True
    assert res.violations == []


def test_check_duplicate_abstractions_clean_code() -> None:
    guard = UBModeGuard()
    clean_src = (
        "class WorkerA:\n"
        "    def run(self) -> int:\n"
        "        return 1\n\n"
        "class DispatcherB:\n"
        "    def dispatch(self, event: str) -> bool:\n"
        "        return True\n"
    )
    res = guard.check_duplicate_abstractions(clean_src)
    assert res.is_compliant is True
    assert res.violations == []


def test_check_duplicate_abstractions_detects_redundant_parallel_classes() -> None:
    guard = UBModeGuard()
    dup_src = (
        "class RequestHelperA:\n"
        "    def format_item(self, item: str) -> str:\n"
        "        return item.strip().lower()\n\n"
        "class RequestHelperB:\n"
        "    def format_item(self, item: str) -> str:\n"
        "        return item.strip().lower()\n"
    )
    res = guard.check_duplicate_abstractions(dup_src)
    assert res.is_compliant is False
    assert res.rule_name in ("NO_DUPLICATION", "DECOHERENCE_CHECK")
    assert len(res.violations) > 0
    assert any("duplicate" in v.lower() or "parallel" in v.lower() for v in res.violations)


def test_check_duplicate_abstractions_handles_syntax_errors() -> None:
    guard = UBModeGuard()
    res = guard.check_duplicate_abstractions("def broken_func(:\n    pass")
    assert isinstance(res, UBModeCheckResult)
    assert res.is_compliant is False
    assert len(res.violations) > 0


def test_evaluate_bus_hook_latency_and_dispatch() -> None:
    guard = UBModeGuard()
    ctx = {
        "event_name": "PreToolUse",
        "payload": {
            "tool_name": "write_file",
            "role": "implementer",
            "modified_files": ["src/module.py"],
            "test_files": ["tests/test_module.py"],
        },
    }
    t0 = time.perf_counter()
    res = guard.evaluate_bus_hook(ctx)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert elapsed_ms < 1.0
    assert isinstance(res, dict)
    assert res.get("decision") in ("allow", "block")


def test_slot_p30_integration_enforces_clean_code_and_tdd_invariants(tmp_path: Path) -> None:
    guard = UBModeGuard()
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)

    compliant_pl = {
        "tool_name": "write_file",
        "role": "implementer",
        "modified_files": ["src/service.py"],
        "test_files": ["tests/test_service.py"],
        "ub_mode_guard": guard,
    }
    res_allow = bus.dispatch("PreToolUse", compliant_pl)
    assert res_allow["ok"] is True
    assert res_allow["decision"] == "allow"

    violating_pl = {
        "tool_name": "write_file",
        "role": "implementer",
        "modified_files": ["src/service.py"],
        "test_files": [],
        "ub_mode_enforce": True,
        "ub_mode_guard": guard,
    }
    res_block = bus.dispatch("PreToolUse", violating_pl)
    assert res_block["decision"] == "block"
    assert "TDD" in str(res_block.get("reason")) or "test" in str(res_block.get("reason")).lower()
