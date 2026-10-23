"""Unified In-Process AgentOps & Hook Multiplexer Bus (agy-golden-stack)."""

from __future__ import annotations

from agy_golden_stack.bus import (
    GoldenStackBus,
    SlotRegistration,
    verify_locked_test_hashes,
)
from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks

__version__ = "1.0.0"

__all__ = [
    "GoldenStackBus",
    "SlotRegistration",
    "__version__",
    "audit_and_consolidate_plugin_hooks",
    "verify_locked_test_hashes",
]
