"""Locked Agile V verification suite for AGY v2.29.0 hooks and script-jail protocol (REQ-GS-V229-01, REQ-GS-V229-02, REQ-GS-V229-03)."""

from __future__ import annotations

from pathlib import Path
import pytest

import agy_golden_stack
from agy_golden_stack.hooks_v229_protocol import (
    HooksV229Protocol,
    auto_harden_run_command_args,
    build_pre_invocation_termination,
    build_pre_tool_use_overwrite_response,
    build_quota_guarded_pre_invocation,
    build_zero_token_user_markdown_step,
    is_remote_linux_container,
    parse_cli_json_finished_reason,
    validate_script_jail_request,
)


def test_req_gs_v229_01_pre_tool_use_overwrite_and_auto_unbuffered_python() -> None:
    """Verify REQ-GS-V229-01 PreToolUse overwrite protocol and auto-unbuffered python -u rewrite."""
    assert getattr(agy_golden_stack, "__v3_generation__", None) == "3.0.0"
    assert agy_golden_stack.HooksV229Protocol is HooksV229Protocol
    assert agy_golden_stack.build_pre_tool_use_overwrite_response is build_pre_tool_use_overwrite_response
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
    assert agy_golden_stack.build_zero_token_user_markdown_step is build_zero_token_user_markdown_step
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
    assert protocol.pre_tool_use_overwrite(
        decision="allow",
        overwrite={"CommandLine": "python -u app.py"},
        reason="Enforce unbuffered I/O",
    )["overwrite"] == {"CommandLine": "python -u app.py"}
    assert protocol.harden_tool_call(
        {"name": "run_command", "args": {"CommandLine": "python script.py"}}
    )["overwrite"] == {"CommandLine": "python -u script.py"}
    assert (
        protocol.zero_token_markdown("## Status\nAll green")["systemMessage"]["metadata"]["user_markdown"]
        == "## Status\nAll green"
    )
    wrapped_jail = protocol.validate_jail(
        "550e8400-e29b-41d4-a716-446655440000",
        timeout_ms=45000,
        rss_kb=524288,
    )
    assert wrapped_jail["resolved_timeout_ms"] == 30000
    assert wrapped_jail["valid"] is True


def test_req_gs_v229_02_termination_and_finished_reason() -> None:
    """Verify REQ-GS-V229-02 PreInvocation termination and CLI JSON finished_reason parsing."""
    assert agy_golden_stack.build_pre_invocation_termination is build_pre_invocation_termination
    assert agy_golden_stack.parse_cli_json_finished_reason is parse_cli_json_finished_reason

    assert build_pre_invocation_termination("Blocked by policy") == {
        "terminationBehavior": "terminate",
        "errorMessage": {"userMessage": "Blocked by policy"},
    }
    assert build_pre_invocation_termination("Blocked by policy", system_message="Gate P30 deny") == {
        "terminationBehavior": "terminate",
        "errorMessage": {
            "userMessage": "Blocked by policy",
            "systemMessage": "Gate P30 deny",
        },
    }
    with pytest.raises(ValueError):
        build_pre_invocation_termination("   ")

    assert parse_cli_json_finished_reason({"response": "ok"}) == {
        "completed_normally": True,
        "finished_reason": None,
        "is_partial": False,
        "should_retry": False,
    }
    assert parse_cli_json_finished_reason({"finished_reason": "print_timeout"}) == {
        "completed_normally": False,
        "finished_reason": "print_timeout",
        "is_partial": True,
        "should_retry": True,
    }
    assert parse_cli_json_finished_reason({"finished_reason": "interrupted"}) == {
        "completed_normally": False,
        "finished_reason": "interrupted",
        "is_partial": True,
        "should_retry": False,
    }
    assert parse_cli_json_finished_reason({"finished_reason": "error"}) == {
        "completed_normally": False,
        "finished_reason": "error",
        "is_partial": False,
        "should_retry": True,
    }
    with pytest.raises(ValueError):
        parse_cli_json_finished_reason({"finished_reason": "unknown_reason"})


def test_req_gs_v229_03_remote_linux_container_and_quota_guard(tmp_path: Path) -> None:
    """Verify REQ-GS-V229-03 remote Linux container detection and quota-guarded PreInvocation."""
    assert agy_golden_stack.is_remote_linux_container is is_remote_linux_container
    assert agy_golden_stack.build_quota_guarded_pre_invocation is build_quota_guarded_pre_invocation

    marker = tmp_path / "container_marker"
    assert is_remote_linux_container(env_root=marker, platform_name="win32") is False
    assert is_remote_linux_container(env_root=marker, platform_name="linux") is True
    marker.write_text("1", encoding="utf-8")
    assert is_remote_linux_container(env_root=marker, platform_name="win32") is True

    idle_term = build_quota_guarded_pre_invocation(
        weekly_burn_fraction=0.25, priority="P3_BACKGROUND_24X7", inbox_changed=False
    )
    assert idle_term["terminationBehavior"] == "terminate"

    quota_term = build_quota_guarded_pre_invocation(
        weekly_burn_fraction=0.85, priority="P2_BATCH", inbox_changed=True
    )
    assert quota_term["terminationBehavior"] == "terminate"

    ok_bg = build_quota_guarded_pre_invocation(
        weekly_burn_fraction=0.50, priority="P3_BACKGROUND_24X7", inbox_changed=True
    )
    assert "systemMessage" in ok_bg and "terminationBehavior" not in ok_bg

    ok_p1 = build_quota_guarded_pre_invocation(
        weekly_burn_fraction=0.92, priority="P1_INTERACTIVE", inbox_changed=False
    )
    assert "systemMessage" in ok_p1 and "terminationBehavior" not in ok_p1
