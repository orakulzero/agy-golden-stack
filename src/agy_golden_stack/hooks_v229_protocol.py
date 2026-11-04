"""AGY v2.29.0 Hooks PreToolUse overwrite, termination, finished_reason, and Script Jail protocol (REQ-GS-V229-01, REQ-GS-V229-02)."""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import Any

REQUIREMENT_ID = "REQ-GS-V229-01"
REQUIREMENT_ID_V229_02 = "REQ-GS-V229-02"
MAX_SCRIPT_JAIL_TIMEOUT_MS = 30000
MAX_SCRIPT_JAIL_RSS_KB = 1048576
SCRIPT_JAIL_PROXY_RULES = "http://127.0.0.1:9"
SCRIPT_JAIL_PROXY_BYPASS_RULES = "<-loopback>"

_FINISHED_REASON_MAP: dict[str, tuple[bool, bool]] = {
    "print_timeout": (True, True),
    "interrupted": (True, False),
    "error": (False, True),
}

_UNBUFFERED_PYTHON_RE = re.compile(r"\b(python(?:3(?:\.\d+)?)?)\b(?!\s+-u\b)")


def build_pre_tool_use_overwrite_response(
    decision: str = "allow",
    overwrite: Mapping[str, Any] | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Construct a v2.29.0 PreToolUse hook response supporting argument overwrite (REQ-GS-V229-01)."""
    return {
        "decision": str(decision),
        "overwrite": dict(overwrite) if overwrite is not None else {},
        "reason": str(reason),
    }


def auto_harden_run_command_args(tool_call: Mapping[str, Any]) -> dict[str, Any]:
    """Auto-rewrite run_command Python invocations to include unbuffered -u flag (REQ-GS-V229-01)."""
    tool_name = str(tool_call.get("name", ""))
    raw_args = tool_call.get("args")
    args_dict = dict(raw_args) if isinstance(raw_args, Mapping) else {}

    overwrite: dict[str, Any] = {}
    rewritten_keys: list[str] = []

    if tool_name == "run_command" and isinstance(args_dict.get("CommandLine"), str):
        cmd = args_dict["CommandLine"]
        new_cmd, count = _UNBUFFERED_PYTHON_RE.subn(r"\1 -u", cmd, count=1)
        if count > 0 and new_cmd != cmd:
            overwrite["CommandLine"] = new_cmd
            rewritten_keys.append("CommandLine")

    return {
        "requirement_id": REQUIREMENT_ID,
        "decision": "allow",
        "overwrite": overwrite,
        "rewritten_keys": rewritten_keys,
    }


def build_zero_token_user_markdown_step(
    user_markdown: str,
    model_system_message: str = "",
) -> dict[str, Any]:
    """Build a zero-token UI-only user_markdown step envelope for v2.29.0 hooks (REQ-GS-V229-01)."""
    return {
        "systemMessage": {
            "systemMessage": str(model_system_message),
            "metadata": {"user_markdown": str(user_markdown)},
        }
    }


def validate_script_jail_request(
    execution_id: str,
    timeout_ms: int = MAX_SCRIPT_JAIL_TIMEOUT_MS,
    rss_kb: int = 262144,
) -> dict[str, Any]:
    """Validate and clamp a v2.29.0 Script Jail execution envelope (REQ-GS-V229-01)."""
    valid_uuid = False
    try:
        parsed = uuid.UUID(str(execution_id))
        valid_uuid = parsed.version == 4 or str(parsed) == str(execution_id).lower()
    except (ValueError, AttributeError, TypeError):
        valid_uuid = False

    resolved_timeout_ms = min(max(int(timeout_ms), 1), MAX_SCRIPT_JAIL_TIMEOUT_MS)
    rss_int = int(rss_kb)
    rss_ok = 0 < rss_int <= MAX_SCRIPT_JAIL_RSS_KB

    return {
        "requirement_id": REQUIREMENT_ID,
        "execution_id": str(execution_id),
        "resolved_timeout_ms": resolved_timeout_ms,
        "rss_kb": rss_int,
        "max_rss_kb": MAX_SCRIPT_JAIL_RSS_KB,
        "proxy_rules": SCRIPT_JAIL_PROXY_RULES,
        "proxy_bypass_rules": SCRIPT_JAIL_PROXY_BYPASS_RULES,
        "valid": bool(valid_uuid and rss_ok),
    }


def build_pre_invocation_termination(
    user_message: str,
    system_message: str | None = None,
) -> dict[str, Any]:
    """Build a PreInvocation hook termination response (REQ-GS-V229-02)."""
    if not isinstance(user_message, str) or not user_message.strip():
        raise ValueError("user_message must be a non-empty string.")
    error_payload: dict[str, str] = {"userMessage": user_message}
    if system_message is not None and str(system_message).strip():
        error_payload["systemMessage"] = str(system_message)
    return {
        "terminationBehavior": "terminate",
        "errorMessage": error_payload,
    }


def parse_cli_json_finished_reason(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Parse AGY CLI --output-format json finished_reason diagnostics (REQ-GS-V229-02)."""
    reason = payload.get("finished_reason")
    if reason is None:
        return {
            "completed_normally": True,
            "finished_reason": None,
            "is_partial": False,
            "should_retry": False,
        }
    if not isinstance(reason, str) or reason not in _FINISHED_REASON_MAP:
        raise ValueError(f"Unsupported finished_reason: {reason!r}")
    is_partial, should_retry = _FINISHED_REASON_MAP[reason]
    return {
        "completed_normally": False,
        "finished_reason": reason,
        "is_partial": is_partial,
        "should_retry": should_retry,
    }


class HooksV229Protocol:
    """Unified v2.29.0 Hooks & Script Jail protocol helper for agy-golden-stack (REQ-GS-V229-01)."""

    requirement_id: str = REQUIREMENT_ID

    def pre_tool_use_overwrite(
        self,
        decision: str = "allow",
        overwrite: Mapping[str, Any] | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        """Build a PreToolUse overwrite decision payload."""
        return build_pre_tool_use_overwrite_response(
            decision=decision,
            overwrite=overwrite,
            reason=reason,
        )

    def harden_tool_call(self, tool_call: Mapping[str, Any]) -> dict[str, Any]:
        """Inspect and auto-harden a run_command tool call with unbuffered Python execution."""
        return auto_harden_run_command_args(tool_call)

    def zero_token_markdown(
        self,
        user_markdown: str,
        model_system_message: str = "",
    ) -> dict[str, Any]:
        """Create a zero-token user_markdown step payload."""
        return build_zero_token_user_markdown_step(
            user_markdown=user_markdown,
            model_system_message=model_system_message,
        )

    def validate_jail(
        self,
        execution_id: str,
        timeout_ms: int = MAX_SCRIPT_JAIL_TIMEOUT_MS,
        rss_kb: int = 262144,
    ) -> dict[str, Any]:
        """Validate a Script Jail request against v2.29.0 limits and loopback sinkhole policy."""
        return validate_script_jail_request(
            execution_id=execution_id,
            timeout_ms=timeout_ms,
            rss_kb=rss_kb,
        )
