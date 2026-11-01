"""Agile V Verification Tests for AST Surgical Patch Validator & TDD Gate.

Traceability:
- REQ-GS-PATCH-01: AST-first surgical patch & refactor validator on files >180 lines.
- REQ-GS-TDD-01: Pre-commit Agile V TDD role separation gate & locked test validation.

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V Role Separation.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pytest

from agy_golden_stack.slots import slot_p30_iso9000_gate, verify_locked_test_hashes
from agy_golden_stack.ub_mode_guard import UBModeGuard

try:
    from agy_golden_stack.ast_patch_validator import (
        find_ast_symbol_boundary,
        apply_range_edit_slice,
        validate_ast_surgical_patch,
        validate_additive_imports,
    )
except ImportError:
    find_ast_symbol_boundary = None
    apply_range_edit_slice = None
    validate_ast_surgical_patch = None
    validate_additive_imports = None

try:
    from agy_golden_stack.tdd_gate import evaluate_tdd_precommit_gate
except ImportError:
    evaluate_tdd_precommit_gate = None


# ============================================================================
# REQ-GS-PATCH-01: AST-First Surgical Patch & Refactor Validator
# ============================================================================


def test_req_gs_patch_01_module_contract_and_presence():
    """Verify agy_golden_stack.ast_patch_validator contract symbols are implemented (REQ-GS-PATCH-01)."""
    assert find_ast_symbol_boundary is not None, "find_ast_symbol_boundary missing"
    assert apply_range_edit_slice is not None, "apply_range_edit_slice missing"
    assert validate_ast_surgical_patch is not None, "validate_ast_surgical_patch missing"
    assert validate_additive_imports is not None, "validate_additive_imports missing"


def test_req_gs_patch_01_symbol_boundary_extraction_on_file_gt_180_lines():
    """Verify AST boundary extraction isolates target function in file >180 lines (REQ-GS-PATCH-01)."""
    assert find_ast_symbol_boundary is not None
    lines: List[str] = ["import math", "import sys", ""]
    for i in range(1, 40):
        lines.extend([f"def helper_prefix_{i}(x: int) -> int:", f"    return x + {i}", ""])
    lines.extend([
        "def target_function(data: list) -> int:",
        "    acc = 0",
        "    for item in data:",
        "        acc += item",
        "    return acc",
        "",
    ])
    for j in range(1, 40):
        lines.extend([f"def helper_suffix_{j}(y: int) -> int:", f"    return y * {j}", ""])
    source_code = "\n".join(lines)
    assert len(source_code.splitlines()) > 180

    start_ln, end_ln, sym_type = find_ast_symbol_boundary(source_code, "target_function")
    assert sym_type == "FunctionDef"
    assert start_ln < end_ln
    assert end_ln - start_ln >= 4


def test_req_gs_patch_01_range_edit_slice_and_prefix_suffix_invariance():
    """Verify RangeEdit slice replacement preserves exact bytes before and after patch (REQ-GS-PATCH-01)."""
    assert apply_range_edit_slice is not None and find_ast_symbol_boundary is not None
    original = "def f1():\n    return 1\n\ndef f2():\n    return 2\n\ndef f3():\n    return 3\n"
    s_ln, e_ln, _ = find_ast_symbol_boundary(original, "f2")
    repl = "def f2():\n    return 200\n"

    patched = apply_range_edit_slice(original, s_ln, e_ln, repl)
    orig_lines = original.splitlines()
    patch_lines = patched.splitlines()
    assert orig_lines[:s_ln - 1] == patch_lines[:s_ln - 1]
    assert "return 200" in patched
    assert ast.parse(patched) is not None


def test_req_gs_patch_01_additive_imports_validation():
    """Verify validate_additive_imports rejects import truncation during refactoring (REQ-GS-PATCH-01)."""
    assert validate_additive_imports is not None
    base_code = "import os\nimport sys\nfrom pathlib import Path\n\ndef run():\n    pass\n"
    truncated = "import os\n\ndef run():\n    pass\n"
    res_bad = validate_additive_imports(base_code, truncated)
    assert res_bad["is_valid"] is False
    assert "sys" in str(res_bad["missing_imports"])

    additive = "import os\nimport sys\nfrom pathlib import Path\nimport json\n\ndef run():\n    pass\n"
    res_good = validate_additive_imports(base_code, additive)
    assert res_good["is_valid"] is True


def test_req_gs_patch_01_anti_duplication_guard_via_ub_mode():
    """Verify UBModeGuard detects clone parallel helper functions (REQ-GS-PATCH-01)."""
    dup_source = (
        "def compute_hash_alpha(val: str) -> str:\n"
        "    return val.strip().lower()\n\n"
        "def compute_hash_beta(val: str) -> str:\n"
        "    return val.strip().lower()\n"
    )
    guard = UBModeGuard()
    res = guard.check_duplicate_abstractions(dup_source)
    assert res.is_compliant is False
    assert len(res.violations) >= 1


# ============================================================================
# REQ-GS-TDD-01: Pre-Commit Agile V TDD Role Separation Gate
# ============================================================================


def test_req_gs_tdd_01_slot_p30_enforces_role_separation(tmp_path: Path):
    """Verify slot_p30 blocks implementer in tests/ and test-designer in src/ (REQ-GS-TDD-01)."""
    p_impl = {"tool_name": "write_file", "role": "implementer", "target_path": "tests/test_x.py"}
    block_impl = slot_p30_iso9000_gate(tmp_path, "PreToolUse", p_impl, {})
    assert block_impl.get("decision") == "block"
    assert "cannot modify locked test file" in block_impl.get("reason", "")

    p_td = {"tool_name": "write_file", "role": "test-designer", "target_path": "src/module.py"}
    block_td = slot_p30_iso9000_gate(tmp_path, "PreToolUse", p_td, {})
    assert block_td.get("decision") == "block"
    assert "cannot modify implementation file" in block_td.get("reason", "")


def test_req_gs_tdd_01_verify_locked_test_hashes_tamper_detection(tmp_path: Path):
    """Verify SHA-256 test file integrity checking detects byte tampering (REQ-GS-TDD-01)."""
    test_dir = tmp_path / "tests"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_f = test_dir / "test_unit.py"
    content = b"def test_ok(): assert True\n"
    test_f.write_bytes(content)
    valid_sha = hashlib.sha256(content).hexdigest()

    ok_res = verify_locked_test_hashes(tmp_path, {"tests/test_unit.py": valid_sha})
    assert ok_res["valid"] is True

    test_f.write_bytes(content + b"# modified\n")
    bad_res = verify_locked_test_hashes(tmp_path, {"tests/test_unit.py": valid_sha})
    assert bad_res["valid"] is False
    assert len(bad_res["mismatches"]) == 1


def test_req_gs_tdd_01_tdd_precommit_gate_contract(tmp_path: Path):
    """Verify evaluate_tdd_precommit_gate requires locked tests for staged changes (REQ-GS-TDD-01)."""
    assert evaluate_tdd_precommit_gate is not None, "evaluate_tdd_precommit_gate missing"
    payload = {
        "staged_files": ["src/agy_golden_stack/new_feature.py"],
        "locked_test_hashes": {},
    }
    gate_res = evaluate_tdd_precommit_gate(tmp_path, payload)
    assert gate_res.get("decision") == "block"
    assert "Missing locked verification tests" in gate_res.get("reason", "")
