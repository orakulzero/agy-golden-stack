"""Tests for src/agy_golden_stack/consolidator.py"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import sys
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks

def test_ignore_agy_golden_stack_plugin(tmp_path: Path) -> None:
    """
    Test that a plugin directory named `agy-golden-stack` containing a `hooks.json`
    with non-empty hooks is ignored, reports zero competing plugins, and creates no backup.
    """
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    
    agy_dir = plugins_dir / "agy-golden-stack"
    agy_dir.mkdir()
    
    hooks_file = agy_dir / "hooks.json"
    hooks_file.write_text(json.dumps({"some_hook": "value"}), encoding="utf-8")
    
    # Run consolidator
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=True)
    
    assert res["ok"] is True
    assert res["competing_plugins_count"] == 0
    assert res["competing_plugins"] == []
    assert res["backups_created"] == []
    
    # Ensure backup was not created
    assert not (agy_dir / "hooks.json.bak").exists()
    
    # Ensure hooks file was not overwritten
    data = json.loads(hooks_file.read_text(encoding="utf-8"))
    assert data == {"some_hook": "value"}

def test_missing_plugins_dir(tmp_path: Path) -> None:
    """Test behavior when the plugins directory does not exist."""
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=False)
    assert res["ok"] is True
    assert res["competing_plugins_count"] == 0

def test_empty_plugins_dir(tmp_path: Path) -> None:
    """Test behavior when the plugins directory is empty."""
    (tmp_path / "plugins").mkdir()
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=False)
    assert res["competing_plugins_count"] == 0

def test_plugin_without_hooks(tmp_path: Path) -> None:
    """Test behavior when a plugin directory lacks hooks.json."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    (plugins_dir / "plugin_no_hooks").mkdir()
    
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=False)
    assert res["competing_plugins_count"] == 0

def test_plugin_invalid_json(tmp_path: Path) -> None:
    """Test behavior when hooks.json contains invalid JSON."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    plugin_dir = plugins_dir / "plugin_invalid"
    plugin_dir.mkdir()
    (plugin_dir / "hooks.json").write_text("invalid json", encoding="utf-8")
    
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=True)
    assert res["competing_plugins_count"] == 1
    assert "plugin_invalid" in res["competing_plugins"]
    assert len(res["backups_created"]) == 1

def test_plugin_already_consolidated(tmp_path: Path) -> None:
    """Test behavior when a plugin's hooks.json is already consolidated."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    plugin_dir = plugins_dir / "plugin_consolidated"
    plugin_dir.mkdir()
    (plugin_dir / "hooks.json").write_text(
        json.dumps({"consolidated_into": "agy-golden-stack"}), encoding="utf-8"
    )
    
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=False)
    assert res["competing_plugins_count"] == 0

def test_competing_plugins_apply_false(tmp_path: Path) -> None:
    """Test detecting competing plugins without applying changes."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    plugin_dir = plugins_dir / "plugin_competing"
    plugin_dir.mkdir()
    (plugin_dir / "hooks.json").write_text(json.dumps({"hooks": {"a": 1}}), encoding="utf-8")
    
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=False)
    assert res["competing_plugins_count"] == 1
    assert res["competing_plugins"] == ["plugin_competing"]
    assert res["backups_created"] == []
    assert not (plugin_dir / "hooks.json.bak").exists()

def test_competing_plugins_apply_true(tmp_path: Path) -> None:
    """Test detecting competing plugins and applying changes."""
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    plugin_dir = plugins_dir / "plugin_competing"
    plugin_dir.mkdir()
    (plugin_dir / "hooks.json").write_text(json.dumps({"hooks": {"a": 1}}), encoding="utf-8")
    
    res = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=True)
    assert res["competing_plugins_count"] == 1
    assert res["competing_plugins"] == ["plugin_competing"]
    assert len(res["backups_created"]) == 1
    
    assert (plugin_dir / "hooks.json.bak").exists()
    
    new_data = json.loads((plugin_dir / "hooks.json").read_text(encoding="utf-8"))
    assert new_data.get("consolidated_into") == "agy-golden-stack"
    assert new_data.get("hooks") == {}
