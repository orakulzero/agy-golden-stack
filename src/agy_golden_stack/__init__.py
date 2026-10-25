"""Unified In-Process AgentOps & Hook Multiplexer Bus (agy-golden-stack)."""

from __future__ import annotations

from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    verify_locked_test_hashes,
)
from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks
from agy_golden_stack.slots import verify_v1_2_station_contracts

__version__ = "1.2.0"

__all__ = [
    "GoldenStackBus",
    "SlotRegistration",
    "__version__",
    "audit_and_consolidate_plugin_hooks",
    "verify_locked_test_hashes",
    "verify_v1_2_station_contracts",
]
