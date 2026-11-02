"""Superagent Worker Mandate Enforcement, Single-Ack Idempotence & Honest Blocker Guard.

Requirement Traceability:
- REQ-GS-MANDATE-01: Worker Mandate Enforcement, Single-Ack Idempotence & Honest Blocker Protocol
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


SLEEP_OR_POLL_PATTERN = re.compile(r"\bsleep\s+\d+|\bgh\s+run\s+watch\b", re.IGNORECASE)


@dataclass(frozen=True)
class WorkerMandate:
    """Execution mandate governing allowed CLI operations for a ticket worker (REQ-GS-MANDATE-01)."""

    ticket_id: str
    repo: str
    allow_merge: bool = False
    allow_issue_close: bool = False
    allow_sleep_polling: bool = False


class SuperagentMandateGuard:
    """Enforces worker CLI restrictions, single acknowledgement idempotence, and blocker report hygiene (REQ-GS-MANDATE-01)."""

    def __init__(self) -> None:
        """Initialize the mandate guard with an empty set of acknowledged trigger IDs (REQ-GS-MANDATE-01)."""
        self._acknowledged_triggers: set[str] = set()

    def verify_worker_command(
        self,
        mandate: WorkerMandate,
        command: str,
    ) -> dict[str, Any]:
        """Validate a worker shell command against the ticket's WorkerMandate (REQ-GS-MANDATE-01)."""
        lowered = command.strip().lower()

        if not mandate.allow_merge and (
            "gh pr merge" in lowered or "--auto" in lowered
        ):
            return {
                "allowed": False,
                "reason": "Direct PR merge and --auto merge are prohibited by worker mandate",
            }

        if not mandate.allow_issue_close and "gh issue close" in lowered:
            return {
                "allowed": False,
                "reason": "Direct issue closure is prohibited by worker mandate",
            }

        if not mandate.allow_sleep_polling and SLEEP_OR_POLL_PATTERN.search(lowered):
            return {
                "allowed": False,
                "reason": "Sleep and polling loops are prohibited; use reactive wakeup subscriptions",
            }

        return {
            "allowed": True,
            "reason": "Command permitted under worker mandate",
        }

    def format_single_acknowledgement(
        self,
        trigger_id: str,
        brief_action: str,
    ) -> dict[str, Any]:
        """Ensure at most one orchestrator acknowledgement comment is emitted per trigger_id (REQ-GS-MANDATE-01)."""
        if trigger_id in self._acknowledged_triggers:
            return {
                "send": False,
                "trigger_id": trigger_id,
                "reason": "already_acknowledged",
                "message": "",
            }

        self._acknowledged_triggers.add(trigger_id)
        return {
            "send": True,
            "trigger_id": trigger_id,
            "reason": "acknowledged",
            "message": f"<!-- orchestrator_ack:{trigger_id} --> On it: {brief_action}",
        }

    def format_worker_report(
        self,
        ticket_id: str,
        status: str,
        summary: str,
        question: str | None = None,
    ) -> dict[str, Any]:
        """Validate and format a worker turn report enforcing single-question blocker discipline (REQ-GS-MANDATE-01)."""
        if status == "blocked_needs_person":
            if question is None or not question.strip():
                raise ValueError(
                    "blocked_needs_person requires a concrete question for the human reviewer"
                )
            cleaned_q = question.strip()
            if cleaned_q.count("?") != 1:
                raise ValueError(
                    "blocked_needs_person requires exactly one question (single '?')"
                )

        return {
            "ticket_id": ticket_id,
            "status": status,
            "summary": summary,
            "question": question,
        }
