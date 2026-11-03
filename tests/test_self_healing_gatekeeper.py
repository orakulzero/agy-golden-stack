"""Locked Agile V (P30) Verification Suite for Autonomous Self-Healing Pipeline Gatekeeper.

Requirement Traceability:
- REQ-GS-GATEKEEPER-01: Diagnostic-to-AST Span Localization, Deterministic Surgical Heal Prompts,
  and Unbalanced Syntax Symbol Fallback Restoration (`self_healing_gatekeeper.py`).

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V Role Separation.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import ast
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.self_healing_gatekeeper import (  # noqa: E402
    SelfHealingGatekeeper,
)

BASELINE_SLOTS_CODE = (
    "from typing import Any\n"
    "\n"
    "DEFAULT_LIMIT = 100\n"
    "\n"
    "def compute_slot(\n"
    "    payload: dict[str, Any],\n"
    "    strict: bool = True,\n"
    ") -> int:\n"
    '    """Compute slot index (REQ-GS-GATEKEEPER-01)."""\n'
    "    return 1 if strict else 0\n"
    "\n"
    "def verify_slot(x: int) -> bool:\n"
    "    return x >= 0\n"
)


def test_parse_gate_diagnostics_maps_syntax_and_missing_symbols_to_ast_spans() -> None:
    """REQ-GS-GATEKEEPER-01: Verify parse_gate_diagnostics maps SyntaxError lines and missing symbols to exact AST symbol spans."""
    gatekeeper = SelfHealingGatekeeper()
    diagnostics = [
        "gate3_ast_req: SyntaxError in src/slots.py: unmatched ')' (<unknown>, line 6)",
        "gate3_ast_req: missing top-level func 'compute_slot' in src/slots.py",
    ]
    source_files = {"src/slots.py": BASELINE_SLOTS_CODE}
    failures = gatekeeper.parse_gate_diagnostics(diagnostics, source_files)

    assert isinstance(failures, list) and len(failures) >= 1
    for item in failures:
        assert item["file_path"] == "src/slots.py"
        assert item["symbol_name"] == "compute_slot"
        assert item["start_line"] == 5
        assert item["end_line"] == 10
        assert isinstance(item.get("defect_kind"), str) and len(item["defect_kind"]) > 0


def test_build_surgical_heal_prompt_includes_numbered_ast_slice() -> None:
    """REQ-GS-GATEKEEPER-01: Verify build_surgical_heal_prompt embeds 1-indexed numbered AST lines and RangeEdit header instructions."""
    gatekeeper = SelfHealingGatekeeper()
    diagnostics = [
        "gate3_ast_req: SyntaxError in src/slots.py: unmatched ')' (<unknown>, line 6)",
    ]
    source_files = {"src/slots.py": BASELINE_SLOTS_CODE}
    failures = gatekeeper.parse_gate_diagnostics(diagnostics, source_files)
    prompt = gatekeeper.build_surgical_heal_prompt(failures, source_files)

    assert isinstance(prompt, str) and len(prompt) > 0
    assert "### RangeEdit: src/slots.py:5-10" in prompt
    assert "def compute_slot" in prompt
    assert "1: " in prompt or "5: " in prompt


def test_auto_repair_unbalanced_syntax_restores_broken_symbol_from_baseline() -> None:
    """REQ-GS-GATEKEEPER-01: Verify auto_repair_unbalanced_syntax restores truncated func_broken from baseline while keeping updated func_ok."""
    gatekeeper = SelfHealingGatekeeper()
    original_code = (
        "def func_ok() -> int:\n"
        '    """Healthy function."""\n'
        "    return 10\n"
        "\n"
        "def func_broken(\n"
        "    x: int,\n"
        "    y: int,\n"
        ") -> int:\n"
        '    """Function that gets truncated."""\n'
        "    return x + y\n"
    )
    broken_code = (
        "def func_ok() -> int:\n"
        '    """Healthy function."""\n'
        "    return 42\n"
        "\n"
        "def func_broken(x,\n"
    )
    res = gatekeeper.auto_repair_unbalanced_syntax(broken_code, original_code)
    assert res["repaired"] is True
    assert "func_broken" in res["restored_symbols"]
    tree = ast.parse(res["code"])
    ns: dict[str, Any] = {}
    exec(compile(tree, "<repaired>", "exec"), ns)
    assert ns["func_ok"]() == 42
    assert ns["func_broken"](3, 4) == 7


def test_auto_repair_unbalanced_syntax_noop_when_already_valid() -> None:
    """REQ-GS-GATEKEEPER-01: Verify auto_repair_unbalanced_syntax is a no-op when candidate code already parses cleanly."""
    gatekeeper = SelfHealingGatekeeper()
    valid_code = "def healthy_fn(a: int) -> int:\n    return a + 1\n"
    res = gatekeeper.auto_repair_unbalanced_syntax(valid_code, valid_code)
    assert res["repaired"] is True
    assert res["restored_symbols"] == []
    assert res["code"] == valid_code


def test_auto_repair_fallback_when_entire_file_corrupted() -> None:
    """REQ-GS-GATEKEEPER-01: Verify auto_repair_unbalanced_syntax falls back to original_code when entire file is unparseable garbage."""
    gatekeeper = SelfHealingGatekeeper()
    original_code = (
        "def baseline_fn() -> str:\n"
        "    return 'stable'\n"
    )
    corrupted_garbage = "))) {{{ unparseable_garbage @@@\n??? def (\n"
    res = gatekeeper.auto_repair_unbalanced_syntax(corrupted_garbage, original_code)
    assert res["repaired"] is True
    assert res["code"] == original_code
    ast.parse(res["code"])
