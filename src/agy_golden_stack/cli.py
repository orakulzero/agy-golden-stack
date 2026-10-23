"""
src/agy_golden_stack/cli.py
CLI Entrypoint for `agy-golden-stack`.
Subcommands:
- `status`      : Report active priority slots P10..P50.
- `dispatch`    : Dispatch an event (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`) through P10..P50.
- `benchmark`   : Benchmark in-memory 5-slot dispatch latency (`avg_duration_ms`).
- `audit-hooks` : Audit or consolidate competing `hooks.json` across installed plugins.
- `audit-repo`  : Run 5-Gate Open-Source Release Audit on a repository directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, List, Optional

from agy_golden_stack.bus import GoldenStackBus
from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks
from agy_golden_stack.slots import audit_repository_5gates


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agy-golden-stack",
        description="Unified In-Process P10..P50 AgentOps & Hook Multiplexer Bus",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_status = sub.add_parser("status", help="Show registered P10..P50 slots")
    p_status.add_argument("--workspace-root", default=None)
    p_status.add_argument("--json", action="store_true")

    p_disp = sub.add_parser("dispatch", help="Dispatch a lifecycle event through P10..P50")
    p_disp.add_argument("event_name", help="Lifecycle event name (e.g. SessionStart, PreToolUse)")
    p_disp.add_argument("--payload", default="{}", help="JSON payload string")
    p_disp.add_argument("--workspace-root", default=None)
    p_disp.add_argument("--json", action="store_true")

    p_bench = sub.add_parser("benchmark", help="Benchmark 5-slot in-process dispatch latency")
    p_bench.add_argument("--iterations", type=int, default=50)
    p_bench.add_argument("--workspace-root", default=None)
    p_bench.add_argument("--json", action="store_true")

    p_hooks = sub.add_parser("audit-hooks", help="Audit or consolidate competing plugin hooks.json")
    p_hooks.add_argument("--config-root", default=None)
    p_hooks.add_argument("--apply", action="store_true")
    p_hooks.add_argument("--json", action="store_true")

    p_repo = sub.add_parser("audit-repo", help="Run 5-Gate OSS Release Audit on a repository")
    p_repo.add_argument("repo_dir", nargs="?", default=".")
    p_repo.add_argument("--json", action="store_true")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.subcommand

    if cmd == "status":
        ws = Path(args.workspace_root) if args.workspace_root else Path.cwd()
        bus = GoldenStackBus(workspace_root=ws)
        _emit(
            {
                "ok": True,
                "slots": [s.slot_id for s in bus.slots],
                "slot_details": [
                    {"slot_id": s.slot_id, "priority": s.priority, "name": s.name}
                    for s in bus.slots
                ],
            }
        )
        return 0

    if cmd == "dispatch":
        ws = Path(args.workspace_root) if args.workspace_root else Path.cwd()
        bus = GoldenStackBus(workspace_root=ws)
        try:
            pl = json.loads(args.payload) if args.payload else {}
        except Exception:
            pl = {}
        res = bus.dispatch(args.event_name, pl)
        _emit(res)
        return 0 if res["decision"] == "allow" else 2

    if cmd == "benchmark":
        ws = Path(args.workspace_root) if args.workspace_root else Path.cwd()
        bus = GoldenStackBus(workspace_root=ws)
        iters = max(1, int(args.iterations))
        durations: List[float] = []
        for _ in range(iters):
            r = bus.dispatch(
                "PreToolUse",
                {
                    "tool_name": "write_file",
                    "role": "implementer",
                    "target_path": "src/module.py",
                    "mcp_tools": ["mcp_short_tool"],
                },
            )
            durations.append(float(r["total_duration_ms"]))
        avg_ms = sum(durations) / len(durations)
        _emit(
            {
                "ok": True,
                "iterations": iters,
                "avg_duration_ms": round(avg_ms, 4),
                "min_duration_ms": round(min(durations), 4),
                "max_duration_ms": round(max(durations), 4),
            }
        )
        return 0

    if cmd == "audit-hooks":
        cfg = (
            Path(args.config_root)
            if args.config_root
            else (Path.home() / ".gemini" / "config")
        )
        res = audit_and_consolidate_plugin_hooks(cfg, apply_changes=args.apply)
        _emit(res)
        return 0

    if cmd == "audit-repo":
        res = audit_repository_5gates(Path(args.repo_dir))
        _emit(res)
        return 0 if res["passed"] else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
