"""Locked Agile V verification suite for AGY v2.29.0 hooks and script-jail protocol (REQ-GS-V229-01)."""

from __future__ import annotations

import agy_golden_stack
from agy_golden_stack.hooks_v229_protocol import (
    HooksV229Protocol,
    auto_harden_run_command_args,
    build_pre_tool_use_overwrite_response,
    build_zero_token_user_markdown_step,
    validate_script_jail_request,
)


def test_req_gs_v229_01_pre_tool_use_overwrite_and_auto_unbuffered_python() -> None:
    """Verify REQ-GS-V229-01 PreToolUse overwrite protocol and auto-unbuffered python -u rewrite."""
    assert getattr(agy_golden_stack, "__v3_generation__", None) == "3.0.0"
    assert agy_golden_stack.HooksV229Protocol is HooksV229Protocol
    assert (
        agy_golden_stack.build_pre_tool_use_overwrite_response
        is build_pre_tool_use_overwrite_response
    )
    assert agy_golden_stack.auto_harden_run_command_args is auto_harden_run_command_args

    resp = build_pre_tool_use_overwrite_response(
        decision="allow",
        overwrite={"CommandLine": "python -u app.py"},
        reason="Enforce unbuffered I/O",
    )
    assert resp == {
        "decision": "allow",
        "overwrite": {"CommandLine": "python -u app.py"},
        "reason": "Enforce unbuffered I/O",
    }

    hardened = auto_harden_run_command_args(
        {"name": "run_command", "args": {"CommandLine": "python script.py"}}
    )
    assert hardened["overwrite"] == {"CommandLine": "python -u script.py"}
    assert hardened["rewritten_keys"] == ["CommandLine"]

    already_unbuffered = auto_harden_run_command_args(
        {"name": "run_command", "args": {"CommandLine": "python -u script.py"}}
    )
    assert already_unbuffered["rewritten_keys"] == []


def test_req_gs_v229_01_zero_token_user_markdown_and_script_jail_policy() -> None:
    """Verify REQ-GS-V229-01 zero-token user_markdown metadata and Script Jail policy validation."""
    assert (
        agy_golden_stack.build_zero_token_user_markdown_step
        is build_zero_token_user_markdown_step
    )
    assert agy_golden_stack.validate_script_jail_request is validate_script_jail_request

    step = build_zero_token_user_markdown_step("## Status\nAll green", model_system_message="")
    assert step == {
        "systemMessage": {
            "systemMessage": "",
            "metadata": {"user_markdown": "## Status\nAll green"},
        }
    }

    jail = validate_script_jail_request(
        "550e8400-e29b-41d4-a716-446655440000",
        timeout_ms=45000,
        rss_kb=524288,
    )
    assert jail["resolved_timeout_ms"] == 30000
    assert jail["proxy_rules"] == "http://127.0.0.1:9"
    assert jail["proxy_bypass_rules"] == "<-loopback>"
    assert jail["valid"] is True

    protocol = HooksV229Protocol()
    wrapped_overwrite = protocol.pre_tool_use_overwrite(
        decision="allow",
        overwrite={"CommandLine": "python -u app.py"},
        reason="Enforce unbuffered I/O",
    )
    assert wrapped_overwrite["overwrite"] == {"CommandLine": "python -u app.py"}

    wrapped_harden = protocol.harden_tool_call(
        {"name": "run_command", "args": {"CommandLine": "python script.py"}}
    )
    assert wrapped_harden["overwrite"] == {"CommandLine": "python -u script.py"}

    wrapped_step = protocol.zero_token_markdown("## Status\nAll green")
    assert (
        wrapped_step["systemMessage"]["metadata"]["user_markdown"]
        == "## Status\nAll green"
    )

    wrapped_jail = protocol.validate_jail(
        "550e8400-e29b-41d4-a716-446655440000",
        timeout_ms=45000,
        rss_kb=524288,
    )
    assert wrapped_jail["resolved_timeout_ms"] == 30000
    assert wrapped_jail["valid"] is True
