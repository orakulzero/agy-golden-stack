"""Unified In-Process AgentOps & Hook Multiplexer Bus (agy-golden-stack)."""

from __future__ import annotations

from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    verify_locked_test_hashes,
    verify_v2_0_station_contracts,
)
from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks
from agy_golden_stack.slots import (
    inspect_computer_use_bus_event,
    verify_v1_2_station_contracts,
    verify_v1_3_station_contracts,
)
from agy_golden_stack.ub_mode_guard import UBModeCheckResult, UBModeGuard

__version__ = "2.0.0"

__all__ = [
    "GoldenStackBus",
    "SlotRegistration",
    "UBModeCheckResult",
    "UBModeGuard",
    "__version__",
    "audit_and_consolidate_plugin_hooks",
    "inspect_computer_use_bus_event",
    "verify_locked_test_hashes",
    "verify_v1_2_station_contracts",
    "verify_v1_3_station_contracts",
    "verify_v2_0_station_contracts",
]
