"""
src/agy_golden_stack/bus.py
Deterministic Single-Process In-Memory Execution Bus (`GoldenStackBus`) for P10..P50 slots.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional

from agy_golden_stack.slots import (
    slot_p10_runtime_doctor,
    slot_p20_brain_memory,
    slot_p30_iso9000_gate,
    slot_p40_lsrpc_plugin,
    slot_p50_oss_release_gate,
    verify_locked_test_hashes,
)

SlotHandler = Callable[[str, Dict[str, Any], Dict[str, Any]], Dict[str, Any]]


@dataclass
class SlotRegistration:
    slot_id: str
    priority: int
    name: str
    handler: SlotHandler


class GoldenStackBus:
    """Single-process P10..P50 lifecycle dispatcher with re-entrancy guard and circuit breaker."""

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        config_root: Optional[Path] = None,
        register_defaults: bool = True,
    ) -> None:
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.config_root = (
            Path(config_root).resolve()
            if config_root
            else (Path.home() / ".gemini" / "config").resolve()
        )
        self.slots: List[SlotRegistration] = []
        self._active_depth = 0

        if register_defaults:
            self._register_default_slots()

    def _register_default_slots(self) -> None:
        self.register_slot(
            slot_id="P10",
            priority=10,
            name="runtime_doctor",
            handler=lambda ev, pl, ctx: slot_p10_runtime_doctor(
                self.workspace_root, ev, pl, ctx
            ),
        )
        self.register_slot(
            slot_id="P20",
            priority=20,
            name="brain_memory",
            handler=lambda ev, pl, ctx: slot_p20_brain_memory(
                self.workspace_root, ev, pl, ctx
            ),
        )
        self.register_slot(
            slot_id="P30",
            priority=30,
            name="iso9000_gate",
            handler=lambda ev, pl, ctx: slot_p30_iso9000_gate(
                self.workspace_root, ev, pl, ctx
            ),
        )
        self.register_slot(
            slot_id="P40",
            priority=40,
            name="lsrpc_plugin",
            handler=lambda ev, pl, ctx: slot_p40_lsrpc_plugin(
                self.workspace_root, ev, pl, ctx
            ),
        )
        self.register_slot(
            slot_id="P50",
            priority=50,
            name="oss_release_gate",
            handler=lambda ev, pl, ctx: slot_p50_oss_release_gate(
                self.workspace_root, ev, pl, ctx
            ),
        )

    def register_slot(
        self,
        slot_id: str,
        priority: int,
        name: str,
        handler: SlotHandler,
    ) -> None:
        """Register a slot and maintain strict ascending priority ordering."""
        self.slots = [s for s in self.slots if s.slot_id != slot_id]
        self.slots.append(
            SlotRegistration(
                slot_id=slot_id,
                priority=int(priority),
                name=name,
                handler=handler,
            )
        )
        self.slots.sort(key=lambda s: (s.priority, s.slot_id))

    def dispatch(
        self,
        event_name: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Dispatch a lifecycle event through P10..P50 in-memory."""
        pl = dict(payload or {})
        context: Dict[str, Any] = {}
        executed_slots: List[str] = []
        slot_timings_ms: Dict[str, float] = {}
        slot_errors: Dict[str, str] = {}

        if self._active_depth > 0 or bool(pl.get("_golden_bus_active")):
            return {
                "ok": True,
                "decision": "allow",
                "event": event_name,
                "reentrant_short_circuit": True,
                "executed_slots": executed_slots,
                "slot_timings_ms": slot_timings_ms,
                "slot_errors": slot_errors,
                "total_duration_ms": 0.0,
                "blocked_by": None,
                "reason": None,
                "context": context,
            }

        t_start = time.perf_counter()
        self._active_depth += 1
        try:
            for slot in self.slots:
                s_start = time.perf_counter()
                try:
                    res = slot.handler(event_name, pl, context) or {}
                except Exception as exc:
                    slot_errors[slot.slot_id] = str(exc)
                    res = {"decision": "allow"}
                s_elapsed = (time.perf_counter() - s_start) * 1000.0
                slot_timings_ms[slot.slot_id] = round(s_elapsed, 4)
                executed_slots.append(slot.slot_id)

                if res.get("decision") == "block":
                    total_elapsed = (time.perf_counter() - t_start) * 1000.0
                    return {
                        "ok": True,
                        "decision": "block",
                        "event": event_name,
                        "reentrant_short_circuit": False,
                        "executed_slots": executed_slots,
                        "slot_timings_ms": slot_timings_ms,
                        "slot_errors": slot_errors,
                        "total_duration_ms": round(total_elapsed, 4),
                        "blocked_by": slot.slot_id,
                        "reason": res.get("reason") or f"Blocked by {slot.slot_id}",
                        "context": context,
                    }

            total_elapsed = (time.perf_counter() - t_start) * 1000.0
            return {
                "ok": True,
                "decision": "allow",
                "event": event_name,
                "reentrant_short_circuit": False,
                "executed_slots": executed_slots,
                "slot_timings_ms": slot_timings_ms,
                "slot_errors": slot_errors,
                "total_duration_ms": round(total_elapsed, 4),
                "blocked_by": None,
                "reason": None,
                "context": context,
            }
        finally:
            self._active_depth -= 1


__all__ = ["GoldenStackBus", "SlotRegistration", "verify_locked_test_hashes"]
