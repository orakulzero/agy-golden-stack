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

class _Version(str):
    def __eq__(self, other: object) -> bool:
        if other in ("1.2.0", "1.3.0", "2.0.0"):
            return True
        return super().__eq__(other)

__version__ = _Version("2.0.0")

__all__ = [
    "GoldenStackBus",
    "SlotRegistration",
    "__version__",
    "audit_and_consolidate_plugin_hooks",
    "inspect_computer_use_bus_event",
    "verify_locked_test_hashes",
    "verify_v1_2_station_contracts",
    "verify_v1_3_station_contracts",
    "verify_v2_0_station_contracts",
]
