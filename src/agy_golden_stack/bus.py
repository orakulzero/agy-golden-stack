"""
src/agy_golden_stack/bus.py
Deterministic Single-Process In-Memory Execution Bus (`GoldenStackBus`) for P10..P50 slots.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
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
        self._telemetry_timings: Dict[str, List[float]] = {}
        self._telemetry_counts: Dict[str, Dict[str, int]] = {}
        self._execution_window: List[Dict[str, Any]] = []
        self._dispatched_events: List[bytes] = []

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
        if slot_id not in self._telemetry_timings:
            self._telemetry_timings[slot_id] = []
        if slot_id not in self._telemetry_counts:
            self._telemetry_counts[slot_id] = {"allow": 0, "block": 0}

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

                sid = slot.slot_id
                if sid not in self._telemetry_timings:
                    self._telemetry_timings[sid] = []
                    self._telemetry_counts[sid] = {"allow": 0, "block": 0}
                self._telemetry_timings[sid].append(s_elapsed)

                is_block = res.get("decision") == "block"
                if is_block:
                    self._telemetry_counts[sid]["block"] += 1
                else:
                    self._telemetry_counts[sid]["allow"] += 1

                if is_block:
                    total_elapsed = (time.perf_counter() - t_start) * 1000.0
                    self._record_dispatch(event_name, pl, slot_errors)
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
            self._record_dispatch(event_name, pl, slot_errors)
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

    def get_telemetry_summary(self) -> Dict[str, Dict[str, Any]]:
        """Compute per-slot SLA telemetry summary including min, avg, p50, p95, max ms and counts."""
        summary: Dict[str, Dict[str, Any]] = {}
        for slot in self.slots:
            sid = slot.slot_id
            timings = self._telemetry_timings.get(sid, [])
            counts = self._telemetry_counts.get(sid, {"allow": 0, "block": 0})
            n = len(timings)
            if n == 0:
                summary[sid] = {
                    "count": 0,
                    "min_ms": 0.0,
                    "avg_ms": 0.0,
                    "p50_ms": 0.0,
                    "p95_ms": 0.0,
                    "max_ms": 0.0,
                    "allow_count": counts.get("allow", 0),
                    "block_count": counts.get("block", 0),
                }
            else:
                sorted_t = sorted(timings)
                summary[sid] = {
                    "count": n,
                    "min_ms": round(sorted_t[0], 4),
                    "avg_ms": round(sum(sorted_t) / n, 4),
                    "p50_ms": round(_compute_percentile(sorted_t, 50.0), 4),
                    "p95_ms": round(_compute_percentile(sorted_t, 95.0), 4),
                    "max_ms": round(sorted_t[-1], 4),
                    "allow_count": counts.get("allow", 0),
                    "block_count": counts.get("block", 0),
                }
        return summary

    def reset_telemetry(self) -> None:
        """Reset all in-memory telemetry timing lists and allow/block counters to empty/zero."""
        for sid in list(self._telemetry_timings.keys()):
            self._telemetry_timings[sid] = []
        for sid in list(self._telemetry_counts.keys()):
            self._telemetry_counts[sid] = {"allow": 0, "block": 0}

    def _record_dispatch(
        self,
        event_name: str,
        payload: Dict[str, Any],
        slot_errors: Dict[str, str],
    ) -> None:
        is_error = len(slot_errors) > 0
        self._execution_window.append({
            "success": not is_error,
            "errors": list(slot_errors.keys()),
            "timestamp": time.time(),
        })
        try:
            event_entry = {
                "event": event_name,
                "payload": payload,
            }
            canonical_bytes = json.dumps(
                event_entry, sort_keys=True, separators=(",", ":"), default=str
            ).encode("utf-8")
        except Exception:
            canonical_bytes = f"{event_name}:{str(payload)}".encode("utf-8")
        self._dispatched_events.append(canonical_bytes)

    def get_circuit_breaker_health(self, window_size: int = 100) -> Dict[str, Any]:
        """Compute sliding-window circuit breaker health across recent dispatches."""
        window = self._execution_window[-window_size:] if window_size > 0 else self._execution_window
        total = len(window)
        if total == 0:
            return {
                "state": "CLOSED",
                "is_tripped": False,
                "failure_rate": 0.0,
                "total_recorded": 0,
                "failure_count": 0,
                "window_size": window_size,
            }
        failures = sum(1 for rec in window if not rec.get("success", True))
        failure_rate = round(failures / total, 4)
        is_tripped = failure_rate >= 0.5
        state = "OPEN" if is_tripped else "CLOSED"
        return {
            "state": state,
            "is_tripped": is_tripped,
            "failure_rate": failure_rate,
            "total_recorded": total,
            "failure_count": failures,
            "window_size": window_size,
        }

    def compute_bus_merkle_digest(self) -> Dict[str, Any]:
        """Compute deterministic RFC 6962 binary Merkle root over all dispatched events."""
        tree = _build_bus_merkle_tree(self._dispatched_events)
        return {
            "merkle_root": tree["root"],
            "root": tree["root"],
            "entry_count": len(self._dispatched_events),
            "tree": tree,
        }


def _build_bus_merkle_tree(leaf_payloads: List[bytes]) -> Dict[str, Any]:
    if not leaf_payloads:
        return {
            "root": "",
            "levels": [],
            "leaf_count": 0,
        }
    current_level: List[str] = [
        hashlib.sha256(b"\x00" + bytes(p)).hexdigest()
        for p in leaf_payloads
    ]
    levels: List[List[str]] = [list(current_level)]
    while len(current_level) > 1:
        if len(current_level) % 2 == 1:
            paired = list(current_level) + [current_level[-1]]
        else:
            paired = current_level
        next_level: List[str] = []
        for i in range(0, len(paired), 2):
            left = bytes.fromhex(paired[i])
            right = bytes.fromhex(paired[i + 1])
            parent = hashlib.sha256(b"\x01" + left + right).hexdigest()
            next_level.append(parent)
        levels.append(next_level)
        current_level = next_level
    return {
        "root": current_level[0],
        "levels": levels,
        "leaf_count": len(leaf_payloads),
    }


def _compute_percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    d = k - f
    return sorted_vals[f] * (1.0 - d) + sorted_vals[c] * d


__all__ = ["GoldenStackBus", "SlotRegistration", "verify_locked_test_hashes"]
