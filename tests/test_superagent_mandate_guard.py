"""Locked Agile V (P30) Verification Suite for Superagent Worker Mandate & Anti-Spam Guard.

Requirement Traceability:
- REQ-GS-MANDATE-01: Worker Mandate Enforcement, Single-Ack Idempotence & Honest Blocker Protocol

Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.superagent_mandate_guard import (  # noqa: E402
    SuperagentMandateGuard,
    WorkerMandate,
)


def test_blocks_direct_pr_merge_auto_merge_and_issue_close_by_default() -> None:
    """REQ-GS-MANDATE-01: Verify gh pr merge, --auto, and gh issue close are blocked by default."""
    guard = SuperagentMandateGuard()
    mandate = WorkerMandate(ticket_id="tkt_1", repo="org/repo")

    res_merge = guard.verify_worker_command(mandate, "gh pr merge 42 --squash")
    assert res_merge["allowed"] is False

    res_auto = guard.verify_worker_command(mandate, "gh pr merge 42 --auto")
    assert res_auto["allowed"] is False

    res_close = guard.verify_worker_command(mandate, "gh issue close 10")
    assert res_close["allowed"] is False


def test_blocks_sleep_and_polling_loops_in_worker_commands() -> None:
    """REQ-GS-MANDATE-01: Verify sleep and CI polling commands are blocked in favor of reactive wakeup."""
    guard = SuperagentMandateGuard()
    mandate = WorkerMandate(ticket_id="tkt_1", repo="org/repo")

    res = guard.verify_worker_command(mandate, "sleep 30 && gh run view")
    assert res["allowed"] is False
    assert "reactive" in res["reason"].lower() or "sleep" in res["reason"].lower()


def test_allows_authorized_gh_pr_create_and_pytest_commands() -> None:
    """REQ-GS-MANDATE-01: Verify normal PR creation and pytest execution commands are allowed."""
    guard = SuperagentMandateGuard()
    mandate = WorkerMandate(ticket_id="tkt_1", repo="org/repo")

    res_pr = guard.verify_worker_command(mandate, "gh pr create --title 'Fix' --body 'Done'")
    assert res_pr["allowed"] is True

    res_test = guard.verify_worker_command(mandate, "pytest -q")
    assert res_test["allowed"] is True


def test_single_acknowledgement_idempotence() -> None:
    """REQ-GS-MANDATE-01: Verify orchestrator sends at most one acknowledgement per trigger_id."""
    guard = SuperagentMandateGuard()
    ack1 = guard.format_single_acknowledgement("trig_99", "Fixing AST parser")
    assert ack1["send"] is True
    assert "Fixing AST parser" in ack1["message"]

    ack2 = guard.format_single_acknowledgement("trig_99", "Fixing AST parser")
    assert ack2["send"] is False
    assert ack2["reason"] == "already_acknowledged"


def test_worker_report_enforces_honest_draft_and_single_question_on_blocker() -> None:
    """REQ-GS-MANDATE-01: Verify blocked_needs_person requires exactly one question."""
    guard = SuperagentMandateGuard()
    report = guard.format_worker_report(
        "tkt_1",
        status="blocked_needs_person",
        summary="Schema ambiguity",
        question="Should user_id be UUID or BIGINT?",
    )
    assert report["ticket_id"] == "tkt_1"
    assert report["status"] == "blocked_needs_person"
    assert report["question"] == "Should user_id be UUID or BIGINT?"

    with pytest.raises(ValueError):
        guard.format_worker_report(
            "tkt_1",
            status="blocked_needs_person",
            summary="Schema ambiguity",
            question=None,
        )

    with pytest.raises(ValueError):
        guard.format_worker_report(
            "tkt_1",
            status="blocked_needs_person",
            summary="Schema ambiguity",
            question="Should user_id be UUID? Also what about index naming?",
        )


def test_req_gs_mandate_01_traceability_and_english_hygiene() -> None:
    """REQ-GS-MANDATE-01: Verify superagent_mandate_guard.py contains REQ-GS-MANDATE-01 and 0 Cyrillic chars."""
    target_file = SRC_ROOT / "agy_golden_stack" / "superagent_mandate_guard.py"
    assert target_file.is_file(), f"Missing target module: {target_file}"
    content = target_file.read_text(encoding="utf-8")
    assert "REQ-GS-MANDATE-01" in content
    for ch in content:
        code = ord(ch)
        assert not (0x0400 <= code <= 0x04FF), f"Cyrillic character found: {ch!r}"
