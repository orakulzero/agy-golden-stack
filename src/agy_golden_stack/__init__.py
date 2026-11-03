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
from agy_golden_stack.self_healing_gatekeeper import SelfHealingGatekeeper

__version__ = "2.0.0"

__all__ = [
    "ASTDeltaVerificationReport",
    "AgenticHandoffProtocol",
    "CrossIDEASTDeltaVerifier",
    "GoldenStackBus",
    "HandoffEnvelope",
    "SelfHealingGatekeeper",
    "SlotRegistration",
    "SuperagentMandateGuard",
    "UBModeCheckResult",
    "UBModeGuard",
    "UserPromptHookInspector",
    "UserPromptInspection",
    "WorkerMandate",
    "__version__",
    "audit_and_consolidate_plugin_hooks",
    "inspect_computer_use_bus_event",
    "verify_locked_test_hashes",
    "verify_v1_2_station_contracts",
    "verify_v1_3_station_contracts",
    "verify_v2_0_station_contracts",
]
