"""
src/agy_golden_stack/consolidator.py
Audits installed plugins for competing multi-process `hooks.json` definitions and
consolidates them into the single-process `agy-golden-stack` dispatcher.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any


def audit_and_consolidate_plugin_hooks(
    config_root: Path,
    apply_changes: bool = False,
) -> dict[str, Any]:
    """
    Scan `<config_root>/plugins/*/hooks.json` for competing hook definitions.
    When `apply_changes=True`, creates `hooks.json.bak` backups and marks them
    consolidated into `agy-golden-stack` so only the single-process bus dispatches.
    """
    croot = Path(config_root).resolve()
    plugins_dir = croot / "plugins"
    competing: list[str] = []
    backups: list[str] = []

    if not plugins_dir.is_dir():
        return {
            "ok": True,
            "competing_plugins_count": 0,
            "competing_plugins": [],
            "applied": bool(apply_changes),
            "backups_created": [],
        }

    for pdir in sorted(plugins_dir.iterdir(), key=lambda p: p.name):
        if not pdir.is_dir() or pdir.name == "agy-golden-stack":
            continue
        hooks_file = pdir / "hooks.json"
        if not hooks_file.is_file():
            continue
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}

        if isinstance(data, dict) and data.get("consolidated_into") == "agy-golden-stack":
            continue

        competing.append(pdir.name)
        if apply_changes:
            bak_file = pdir / "hooks.json.bak"
            shutil.copy2(hooks_file, bak_file)
            backups.append(str(bak_file))
            consolidated_payload = {
                "consolidated_into": "agy-golden-stack",
                "hooks": {},
            }
            hooks_file.write_text(
                json.dumps(consolidated_payload, indent=2) + "\n",
                encoding="utf-8",
            )

    return {
        "ok": True,
        "competing_plugins_count": len(competing),
        "competing_plugins": competing,
        "applied": bool(apply_changes),
        "backups_created": backups,
    }
