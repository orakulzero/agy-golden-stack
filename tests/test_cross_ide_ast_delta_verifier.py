"""Locked Agile V (P30) Verification Suite for Cross-IDE AST Delta Verifier.

Requirement Traceability:
- REQ-GS-DELTAVERIFY-01: Cross-IDE AST Delta Verifier (`cross_ide_ast_delta_verifier.py`)

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V Role Separation.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.cross_ide_ast_delta_verifier import (  # noqa: E402
    ASTDeltaVerificationReport,
    CrossIDEASTDeltaVerifier,
)

BASELINE_SRC = (
    "class Processor:\n"
    "    @staticmethod\n"
    "    def process(x: int) -> int:\n"
    '        """Execute processing step (REQ-GS-01)."""\n'
    "        result = x + 1\n"
    "        return result\n"
)


def test_valid_refactoring_preserves_signatures_decorators_and_req_tags() -> None:
    """REQ-GS-DELTAVERIFY-01: Verify clean refactoring preserving signatures, decorators, and REQ tags passes."""
    ver = CrossIDEASTDeltaVerifier()
    after_src = (
        "class Processor:\n"
        "    @staticmethod\n"
        "    def process(x: int) -> int:\n"
        '        """Execute optimized processing step (REQ-GS-01)."""\n'
        "        return x + 1\n"
    )
    rep = ver.verify_ast_delta(BASELINE_SRC, after_src)
    assert isinstance(rep, ASTDeltaVerificationReport)
    assert rep.passed is True
    assert rep.dropped_symbols == []
    assert rep.dropped_decorators == []
    assert rep.dropped_req_tags == []
    assert rep.dropped_return_annotations == []
    assert rep.complexity_violations == []


def test_dropped_public_symbol_or_decorator_fails_verification() -> None:
    """REQ-GS-DELTAVERIFY-01: Verify removing @staticmethod or deleting a public symbol fails verification."""
    ver = CrossIDEASTDeltaVerifier()
    no_decorator_src = (
        "class Processor:\n"
        "    def process(x: int) -> int:\n"
        '        """Execute processing step (REQ-GS-01)."""\n'
        "        return x + 1\n"
    )
    rep_dec = ver.verify_ast_delta(BASELINE_SRC, no_decorator_src)
    assert rep_dec.passed is False
    assert len(rep_dec.dropped_decorators) >= 1

    dropped_sym_src = "class Processor:\n    pass\n"
    rep_sym = ver.verify_ast_delta(BASELINE_SRC, dropped_sym_src)
    assert rep_sym.passed is False
    assert len(rep_sym.dropped_symbols) >= 1


def test_dropped_return_type_annotation_or_req_tag_fails_verification() -> None:
    """REQ-GS-DELTAVERIFY-01: Verify stripping return type annotation or REQ-GS-01 docstring tag fails verification."""
    ver = CrossIDEASTDeltaVerifier()
    no_ret_src = (
        "class Processor:\n"
        "    @staticmethod\n"
        "    def process(x: int):\n"
        '        """Execute processing step (REQ-GS-01)."""\n'
        "        return x + 1\n"
    )
    rep_ret = ver.verify_ast_delta(BASELINE_SRC, no_ret_src)
    assert rep_ret.passed is False
    assert len(rep_ret.dropped_return_annotations) >= 1

    no_req_src = (
        "class Processor:\n"
        "    @staticmethod\n"
        "    def process(x: int) -> int:\n"
        '        """Execute processing step without tag."""\n'
        "        return x + 1\n"
    )
    rep_req = ver.verify_ast_delta(BASELINE_SRC, no_req_src)
    assert rep_req.passed is False
    assert "REQ-GS-01" in rep_req.dropped_req_tags


def test_cyclomatic_complexity_spike_flagged() -> None:
    """REQ-GS-DELTAVERIFY-01: Verify refactoring that spikes cyclomatic complexity above max_complexity_delta fails."""
    ver = CrossIDEASTDeltaVerifier(max_complexity_delta=8)
    branches = "\n".join(f"        if x == {i}:\n            x += {i}" for i in range(12))
    spiked_src = (
        "class Processor:\n"
        "    @staticmethod\n"
        "    def process(x: int) -> int:\n"
        '        """Execute processing step (REQ-GS-01)."""\n'
        f"{branches}\n"
        "        return x\n"
    )
    rep = ver.verify_ast_delta(BASELINE_SRC, spiked_src)
    assert rep.passed is False
    assert len(rep.complexity_violations) >= 1


def test_cross_verify_dual_agent_candidates_selects_safer_ast() -> None:
    """REQ-GS-DELTAVERIFY-01: Verify select_safer_candidate picks the compliant candidate with lower complexity delta."""
    ver = CrossIDEASTDeltaVerifier(max_complexity_delta=8)
    cand_a_bad = "class Processor:\n    pass\n"
    cand_b_clean = (
        "class Processor:\n"
        "    @staticmethod\n"
        "    def process(x: int) -> int:\n"
        '        """Execute processing step (REQ-GS-01)."""\n'
        "        return x + 1\n"
    )
    selection = ver.select_safer_candidate(BASELINE_SRC, cand_a_bad, cand_b_clean)
    assert selection["selected"] == "candidate_b"
    assert selection["selected_source"] == cand_b_clean
    assert selection["report"].passed is True


def test_req_gs_deltaverify_01_traceability_and_english_hygiene() -> None:
    """REQ-GS-DELTAVERIFY-01: Verify cross_ide_ast_delta_verifier.py contains REQ-GS-DELTAVERIFY-01 and 0 Cyrillic chars."""
    target_file = SRC_ROOT / "agy_golden_stack" / "cross_ide_ast_delta_verifier.py"
    assert target_file.is_file(), f"Missing target module: {target_file}"
    content = target_file.read_text(encoding="utf-8")
    assert "REQ-GS-DELTAVERIFY-01" in content
    for ch in content:
        code = ord(ch)
        assert not (0x0400 <= code <= 0x04FF), f"Cyrillic character found: {ch!r}"
