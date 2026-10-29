"""Agile V Locked Verification Tests for AGY v2.28.0 Pre-Prompt Hook.

REQ-BUS-PROMPT-01: Verifies UserPromptInspection frozen dataclass contract and
UserPromptHookInspector secret redaction, execution mode routing, and <5.0ms SLA.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any, Dict
import pytest

from agy_golden_stack.prompt_hook import (
    UserPromptHookInspector,
    UserPromptInspection,
)


def test_user_prompt_inspection_frozen_dataclass_contract() -> None:
    """@requirement("REQ-BUS-PROMPT-01")
    Verify UserPromptInspection is a frozen dataclass with all required fields.
    """
    inspection = UserPromptInspection(
        allowed=True,
        sanitized_message="Run unit tests cleanly.",
        redacted_secrets_count=0,
        redacted_tags=[],
        recommended_execution_mode="fold_in_process",
        latency_ms=0.12,
    )
    assert inspection.allowed is True
    assert inspection.sanitized_message == "Run unit tests cleanly."
    assert inspection.redacted_secrets_count == 0
    assert inspection.redacted_tags == []
    assert inspection.recommended_execution_mode == "fold_in_process"
    assert inspection.latency_ms == 0.12

    with pytest.raises(dataclasses.FrozenInstanceError):
        inspection.allowed = False  # type: ignore[misc]


def test_inspect_user_message_extracts_payload_keys_and_folds_in_process() -> None:
    """@requirement("REQ-BUS-PROMPT-01")
    Verify extraction of user_message, prompt, or message keys and default fold_in_process mode.
    """
    inspector = UserPromptHookInspector()
    for key in ("user_message", "prompt", "message"):
        payload: Dict[str, Any] = {key: "Refactor helper function in utils.py"}
        res = inspector.inspect_user_message(payload)
        assert isinstance(res, UserPromptInspection)
        assert res.allowed is True
        assert res.sanitized_message == "Refactor helper function in utils.py"
        assert res.redacted_secrets_count == 0
        assert res.redacted_tags == []
        assert res.recommended_execution_mode == "fold_in_process"
        assert 0.0 <= res.latency_ms < 5.0


def test_inspect_user_message_redacts_inline_credentials_deterministically() -> None:
    """@requirement("REQ-BUS-PROMPT-01")
    Verify inline API keys and cookies are replaced with deterministic [REDACTED_DPAPI:<sha256_12>] tags.
    """
    inspector = UserPromptHookInspector()
    gkey = "AIza" + "SyD9876543210abcdefghij12345"
    ghp = "ghp_" + "1234567890abcdefghijklmnopqrstuv"
    sk = "sk-" + "proj1234567890abcdefghijklmnopqr"
    psid = "__Secure-1PSID=session_token_value_987654321"

    raw_prompt = (
        f"Check keys: google={gkey} github={ghp} "
        f"openai={sk} cookie={psid};"
    )
    res1 = inspector.inspect_user_message({"user_message": raw_prompt})
    res2 = inspector.inspect_user_message({"user_message": raw_prompt})

    assert res1.redacted_secrets_count == 4
    assert len(res1.redacted_tags) == 4
    assert res1.sanitized_message == res2.sanitized_message
    assert res1.redacted_tags == res2.redacted_tags

    for secret in (gkey, ghp, sk, psid):
        assert secret not in res1.sanitized_message
        expected_hash12 = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
        expected_tag = f"[REDACTED_DPAPI:{expected_hash12}]"
        assert expected_tag in res1.redacted_tags
        assert expected_tag in res1.sanitized_message

    for tag in res1.redacted_tags:
        assert re.fullmatch(r"\[REDACTED_DPAPI:[0-9a-f]{12}\]", tag)
    assert 0.0 <= res1.latency_ms < 5.0


def test_inspect_user_message_routes_spawn_subagent_triggers() -> None:
    """@requirement("REQ-BUS-PROMPT-01")
    Verify recommended_execution_mode is spawn_subagent on teamwork, parallel branches, Agile V, or >500 lines.
    """
    inspector = UserPromptHookInspector()

    subagent_payloads = [
        {"user_message": "Execute /teamwork across all stations."},
        {"user_message": "Launch parallel branches to benchmark modules."},
        {"user_message": "Enforce Agile V role isolation for test-designer and implementer."},
        {"user_message": "Inspect build output.", "estimated_context_lines": 750},
        {"user_message": "Please inspect >500-line log dump from production."},
    ]
    for pl in subagent_payloads:
        res = inspector.inspect_user_message(pl)
        assert res.recommended_execution_mode == "spawn_subagent", f"Failed for payload: {pl}"
        assert 0.0 <= res.latency_ms < 5.0

    fold_payload = {
        "user_message": "Check status of single unit test.",
        "estimated_context_lines": 120,
    }
    res_fold = inspector.inspect_user_message(fold_payload)
    assert res_fold.recommended_execution_mode == "fold_in_process"
    assert 0.0 <= res_fold.latency_ms < 5.0


def test_inspect_user_message_handles_empty_payload_under_sla() -> None:
    """@requirement("REQ-BUS-PROMPT-01")
    Verify graceful handling of empty payloads within the <5.0ms latency budget.
    """
    inspector = UserPromptHookInspector()
    res = inspector.inspect_user_message({})
    assert res.allowed is True
    assert res.sanitized_message == ""
    assert res.redacted_secrets_count == 0
    assert res.redacted_tags == []
    assert res.recommended_execution_mode == "fold_in_process"
    assert 0.0 <= res.latency_ms < 5.0
