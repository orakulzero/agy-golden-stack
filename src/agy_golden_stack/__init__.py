"""Unified In-Process AgentOps & Hook Multiplexer Bus (agy-golden-stack)."""

from __future__ import annotations

from agy_golden_stack.agentic_handoff import (
    AgenticHandoffProtocol,
    HandoffEnvelope,
)
from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    verify_locked_test_hashes,
    verify_v2_0_station_contracts,
)
from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks
from agy_golden_stack.prompt_hook import (
    UserPromptHookInspector,
    UserPromptInspection,
)
from agy_golden_stack.slots import (
    inspect_computer_use_bus_event,
    verify_v1_2_station_contracts,
    verify_v1_3_station_contracts,
)
from agy_golden_stack.ub_mode_guard import UBModeCheckResult, UBModeGuard
from agy_golden_stack.superagent_mandate_guard import (
    SuperagentMandateGuard,
    WorkerMandate,
)
from agy_golden_stack.cross_ide_ast_delta_verifier import (
    ASTDeltaVerificationReport,
    CrossIDEASTDeltaVerifier,
)
from agy_golden_stack.hooks_v229_protocol import (
    HooksV229Protocol,
    auto_harden_run_command_args,
    build_pre_invocation_termination,
    build_pre_tool_use_overwrite_response,
    build_zero_token_user_markdown_step,
    parse_cli_json_finished_reason,
    validate_script_jail_request,
)
from agy_golden_stack.self_healing_gatekeeper import SelfHealingGatekeeper

__version__ = "2.0.0"
__v3_generation__ = "3.0.0"

__all__ = [
    "ASTDeltaVerificationReport",
    "AgenticHandoffProtocol",
    "CrossIDEASTDeltaVerifier",
    "GoldenStackBus",
    "HandoffEnvelope",
    "HooksV229Protocol",
    "SelfHealingGatekeeper",
    "SlotRegistration",
    "SuperagentMandateGuard",
    "UBModeCheckResult",
    "UBModeGuard",
    "UserPromptHookInspector",
    "UserPromptInspection",
    "WorkerMandate",
    "__v3_generation__",
    "__version__",
    "audit_and_consolidate_plugin_hooks",
    "auto_harden_run_command_args",
    "build_pre_invocation_termination",
    "build_pre_tool_use_overwrite_response",
    "build_zero_token_user_markdown_step",
    "inspect_computer_use_bus_event",
    "parse_cli_json_finished_reason",
    "validate_script_jail_request",
    "verify_locked_test_hashes",
    "verify_v1_2_station_contracts",
    "verify_v1_3_station_contracts",
    "verify_v2_0_station_contracts",
]
