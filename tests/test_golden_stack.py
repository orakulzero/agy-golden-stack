"""Agile V Isolated Test Suite for agy-golden-stack (BL-20261023-GOLDEN-L3).

Covers REQ-001 through REQ-005 with strict self-match avoidance:
all forbidden personal strings and Cyrillic codepoints are constructed
dynamically at runtime via chr() and string concatenation.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _sample_cyrillic_word() -> str:
    """Construct a sample Cyrillic string dynamically without literal characters."""
    return "".join(chr(c) for c in (1055, 1088, 1080, 1074, 1077, 1090))


def _forbidden_tokens() -> list[str]:
    """Construct forbidden PII/local tokens dynamically to prevent self-matching."""
    t1 = "Ora" + "kul" + " " + "Grey"
    t2 = "Ora" + "kul"
    t3 = "ANTI" + "GRAVITY"
    t4 = "kuro" + "ora" + "kul" + "grey"
    return [t1, t2, t3, t4]


def _has_cyrillic(text: str) -> bool:
    """Return True if any character falls within the Cyrillic Unicode block."""
    return any(0x0400 <= ord(ch) <= 0x04FF for ch in text)


# ============================================================================
# REQ-001: GoldenStackBus Priority Ordering, Re-Entrancy & Circuit Breaker
# ============================================================================


def test_req001_default_slots_and_priority_order(tmp_path: Path) -> None:
    """Verify GoldenStackBus registers P10..P50 in strict ascending priority order."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    slot_ids = [slot.slot_id for slot in bus.slots]
    assert slot_ids == ["P10", "P20", "P30", "P40", "P50"]

    res = bus.dispatch("SessionStart", {"prompt": "hello world"})
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert res["event"] == "SessionStart"
    assert res["reentrant_short_circuit"] is False
    assert res["executed_slots"] == ["P10", "P20", "P30", "P40", "P50"]
    assert res["blocked_by"] is None
    assert isinstance(res["total_duration_ms"], float)
    for sid in ("P10", "P20", "P30", "P40", "P50"):
        assert sid in res["slot_timings_ms"]
        assert res["slot_timings_ms"][sid] >= 0.0


def test_req001_reentrancy_guard_flag_and_nested_call(tmp_path: Path) -> None:
    """Verify re-entrancy guard prevents recursive infinite hook loops."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)

    # 1. Explicit payload flag short-circuit
    flagged_res = bus.dispatch("PreToolUse", {"_golden_bus_active": True})
    assert flagged_res["ok"] is True
    assert flagged_res["decision"] == "allow"
    assert flagged_res["reentrant_short_circuit"] is True
    assert flagged_res["executed_slots"] == []

    # 2. Nested dispatch inside a custom slot handler
    nested_results: list[Dict[str, Any]] = []

    def _reentrant_slot(event_name: str, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        nested_results.append(bus.dispatch(event_name, {"nested": True}))
        return {"decision": "allow"}

    bus.register_slot(slot_id="P15", priority=15, name="reentrant_probe", handler=_reentrant_slot)
    outer_res = bus.dispatch("SessionStart", {})
    assert outer_res["reentrant_short_circuit"] is False
    assert "P15" in outer_res["executed_slots"]
    assert len(nested_results) == 1
    assert nested_results[0]["reentrant_short_circuit"] is True
    assert nested_results[0]["decision"] == "allow"


def test_req001_circuit_breaker_isolates_non_blocking_slot_exception(tmp_path: Path) -> None:
    """Verify circuit breaker catches RuntimeError in a slot and continues execution."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)

    def _boom_slot(event_name: str, payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        raise RuntimeError("boom")

    bus.register_slot(slot_id="P25", priority=25, name="faulty_slot", handler=_boom_slot)
    res = bus.dispatch("SessionStart", {})
    assert res["ok"] is True
    assert res["decision"] == "allow"
    assert "P25" in res["slot_errors"]
    assert "boom" in res["slot_errors"]["P25"]
    assert "P30" in res["executed_slots"]
    assert "P50" in res["executed_slots"]


# ============================================================================
# REQ-002: P10 Runtime Doctor & P20 Brain Memory In-Process Slots
# ============================================================================


def test_req002_p10_heals_stale_git_index_lock(tmp_path: Path) -> None:
    """Verify P10 detects and removes stale .git/index.lock files."""
    from agy_golden_stack.bus import GoldenStackBus

    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True)
    lock_file = git_dir / "index.lock"
    lock_file.write_text("stale lock", encoding="utf-8")
    stale_time = time.time() - 600
    os.utime(lock_file, (stale_time, stale_time))

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch("SessionStart", {"stale_lock_threshold_sec": 60})
    assert not lock_file.exists()
    assert len(res["context"]["healed_git_locks"]) == 1


def test_req002_p10_mcp_64char_and_bigint_sanitization(tmp_path: Path) -> None:
    """Verify P10 flags >64-char MCP tool names and coerces unsafe JS BigInts."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    long_tool = "mcp_server_" + ("x" * 60)
    short_tool = "mcp_server_short_tool"
    unsafe_int = 9007199254740992  # JS MAX_SAFE_INTEGER + 1

    res = bus.dispatch(
        "PreToolUse",
        {
            "mcp_tools": [short_tool, long_tool],
            "subagent_id": unsafe_int,
            "nested": {"trace_id": unsafe_int + 99},
        },
    )
    assert long_tool in res["context"]["mcp_64char_violations"]
    assert short_tool not in res["context"]["mcp_64char_violations"]
    assert res["context"]["coerced_bigints"]["subagent_id"] == str(unsafe_int)
    assert res["context"]["coerced_bigints"]["nested.trace_id"] == str(unsafe_int + 99)


def test_req002_p20_brain_memory_conversation_links(tmp_path: Path) -> None:
    """Verify P20 validates markdown conversation:// links and flags bare links."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    prompt_text = (
        "Valid ref [Prior Session](conversation://11111111-2222-3333-4444-555555555555) "
        "and bare ref conversation://99999999-8888-7777-6666-555555555555 in text."
    )
    res = bus.dispatch("SessionStart", {"prompt": prompt_text})
    assert "conversation://99999999-8888-7777-6666-555555555555" in res["context"]["bare_conversation_links"]
    assert "conversation://11111111-2222-3333-4444-555555555555" not in res["context"]["bare_conversation_links"]
    assert "conversation://11111111-2222-3333-4444-555555555555" in res["context"]["valid_conversation_links"]


# ============================================================================
# REQ-003: P30 ISO 9001 Agile V Self-Grading Bias Gate & Locked Test Hashes
# ============================================================================


def test_req003_p30_blocks_implementer_modifying_tests(tmp_path: Path) -> None:
    """Verify P30 blocks implementer/build-agent from modifying files inside tests/."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "write_file",
            "role": "implementer",
            "target_path": "tests/test_feature.py",
        },
    )
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P30"
    assert "Self-Grading Bias" in (res["reason"] or "")
    assert "P40" not in res["executed_slots"]
    assert "P50" not in res["executed_slots"]


def test_req003_p30_blocks_test_designer_modifying_src(tmp_path: Path) -> None:
    """Verify P30 blocks test-designer from modifying implementation files in src/."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "edit_file",
            "role": "test-designer",
            "target_path": "src/agy_golden_stack/bus.py",
        },
    )
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P30"
    assert "Self-Grading Bias" in (res["reason"] or "")


def test_req003_p30_allows_valid_role_file_combinations(tmp_path: Path) -> None:
    """Verify P30 allows implementer on src/ and test-designer on tests/."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res_impl = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "write_file",
            "role": "implementer",
            "target_path": "src/app.py",
        },
    )
    assert res_impl["decision"] == "allow"

    res_td = bus.dispatch(
        "PreToolUse",
        {
            "tool_name": "write_file",
            "role": "test-designer",
            "target_path": "tests/test_app.py",
        },
    )
    assert res_td["decision"] == "allow"


def test_req003_verify_locked_test_hashes(tmp_path: Path) -> None:
    """Verify SHA-256 locked test verification detects any 1-byte tampering."""
    from agy_golden_stack.bus import verify_locked_test_hashes

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_sample.py"
    content = b"def test_ok():\n    assert 1 + 1 == 2\n"
    test_file.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    locked = {"tests/test_sample.py": digest}
    ok_check = verify_locked_test_hashes(tmp_path, locked)
    assert ok_check["valid"] is True
    assert ok_check["mismatches"] == []

    # Tamper by 1 byte
    test_file.write_bytes(content + b"\n")
    bad_check = verify_locked_test_hashes(tmp_path, locked)
    assert bad_check["valid"] is False
    assert len(bad_check["mismatches"]) == 1
    assert bad_check["mismatches"][0]["path"] == "tests/test_sample.py"


# ============================================================================
# REQ-004: P40 LSRPC Plugin Validator, P50 5-Gate OSS Release & Consolidator
# ============================================================================


def test_req004_p40_validates_plugin_structure(tmp_path: Path) -> None:
    """Verify P40 validates plugin.json keys, root hooks.json, and frontmatter-free AGENTS.md."""
    from agy_golden_stack.bus import GoldenStackBus

    plugin_dir = tmp_path / "plugins" / "sample-plugin"
    (plugin_dir / "rules").mkdir(parents=True)
    (plugin_dir / "plugin.json").write_text(
        json.dumps(
            {
                "name": "sample-plugin",
                "version": "0.1.0",
                "description": "Valid sample plugin",
                "rules": "./rules",
                "hooks": "./hooks.json",
            }
        ),
        encoding="utf-8",
    )
    (plugin_dir / "hooks.json").write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    (plugin_dir / "rules" / "AGENTS.md").write_text("# Sample Rules\n\n1. English only.\n", encoding="utf-8")

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch("SessionStart", {"plugin_dir": str(plugin_dir)})
    val = res["context"]["plugin_validation"]
    assert val["valid"] is True
    assert val["errors"] == []


def test_req004_p40_detects_invalid_plugin_manifest_and_frontmatter(tmp_path: Path) -> None:
    """Verify P40 flags unsupported plugin.json keys and forbidden YAML frontmatter in AGENTS.md."""
    from agy_golden_stack.bus import GoldenStackBus

    bad_plugin = tmp_path / "plugins" / "bad-plugin"
    (bad_plugin / "rules").mkdir(parents=True)
    (bad_plugin / "plugin.json").write_text(
        json.dumps(
            {
                "name": "bad-plugin",
                "version": "0.1.0",
                "unsupported_secret_key": True,
            }
        ),
        encoding="utf-8",
    )
    (bad_plugin / "rules" / "AGENTS.md").write_text(
        "---\ntitle: Forbidden Frontmatter\n---\n# Bad Rules\n",
        encoding="utf-8",
    )

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch("SessionStart", {"plugin_dir": str(bad_plugin)})
    val = res["context"]["plugin_validation"]
    assert val["valid"] is False
    assert len(val["errors"]) >= 2


def test_req004_p50_blocks_git_push_on_forbidden_personal_token(tmp_path: Path) -> None:
    """Verify P50 blocks gh release create or git push when forbidden personal tokens exist."""
    from agy_golden_stack.bus import GoldenStackBus

    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026\n", encoding="utf-8")
    leaked_file = tmp_path / "config.yaml"
    leaked_file.write_text("user_path: C:/Users/" + _forbidden_tokens()[0] + "/app\n", encoding="utf-8")

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    res = bus.dispatch(
        "PreToolUse",
        {"tool_name": "run_command", "command": "gh release create v1.0.0"},
    )
    assert res["decision"] == "block"
    assert res["blocked_by"] == "P50"


def test_req004_p50_blocks_git_push_on_missing_license_or_cyrillic(tmp_path: Path) -> None:
    """Verify P50 blocks git push when LICENSE is missing or Cyrillic/PII exists."""
    from agy_golden_stack.bus import GoldenStackBus

    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)

    # 1. Missing LICENSE
    res_no_lic = bus.dispatch(
        "PreToolUse",
        {"tool_name": "run_command", "command": "git push origin main"},
    )
    assert res_no_lic["decision"] == "block"
    assert res_no_lic["blocked_by"] == "P50"

    # 2. Add MIT LICENSE but inject Cyrillic into a tracked file
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026\n", encoding="utf-8")
    bad_file = tmp_path / "README.md"
    bad_file.write_text("Hello " + _sample_cyrillic_word() + "\n", encoding="utf-8")

    res_cyr = bus.dispatch(
        "PreToolUse",
        {"tool_name": "run_command", "command": "git push origin main"},
    )
    assert res_cyr["decision"] == "block"
    assert res_cyr["blocked_by"] == "P50"

    # 3. Clean file -> allow
    bad_file.write_text("# Clean Repository\n\nAll English documentation.\n", encoding="utf-8")
    res_clean = bus.dispatch(
        "PreToolUse",
        {"tool_name": "run_command", "command": "git push origin main"},
    )
    assert res_clean["decision"] == "allow"


def test_req004_hook_consolidator_deduplicates_competing_plugins(tmp_path: Path) -> None:
    """Verify audit_and_consolidate_plugin_hooks backs up and consolidates hooks.json."""
    from agy_golden_stack.consolidator import audit_and_consolidate_plugin_hooks

    plugins_root = tmp_path / "plugins"
    for name in ("agy-doctor-mux", "agy-brain-memory", "iso9000-agentops"):
        pdir = plugins_root / name
        pdir.mkdir(parents=True)
        (pdir / "hooks.json").write_text(
            json.dumps(
                {
                    "hooks": {
                        "SessionStart": [
                            {
                                "matcher": "*",
                                "hooks": [{"type": "command", "command": f"python {name}.py"}],
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )

    dry_report = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=False)
    assert dry_report["competing_plugins_count"] == 3
    assert dry_report["applied"] is False
    assert not (plugins_root / "agy-doctor-mux" / "hooks.json.bak").exists()

    apply_report = audit_and_consolidate_plugin_hooks(tmp_path, apply_changes=True)
    assert apply_report["applied"] is True
    assert len(apply_report["backups_created"]) == 3
    for name in ("agy-doctor-mux", "agy-brain-memory", "iso9000-agentops"):
        bak = plugins_root / name / "hooks.json.bak"
        rewritten = json.loads((plugins_root / name / "hooks.json").read_text(encoding="utf-8"))
        assert bak.exists()
        assert rewritten.get("consolidated_into") == "agy-golden-stack"


# ============================================================================
# REQ-005: CLI, Benchmark (<10ms) & 5-Gate Repository Hygiene
# ============================================================================


def test_req005_cli_status_and_dispatch(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify CLI status and dispatch commands output valid JSON."""
    from agy_golden_stack import cli

    rc_status = cli.main(["status", "--json"])
    assert rc_status == 0
    out_status = json.loads(capsys.readouterr().out)
    assert out_status["ok"] is True
    assert out_status["slots"] == ["P10", "P20", "P30", "P40", "P50"]

    rc_disp = cli.main(["dispatch", "SessionStart", "--payload", "{}", "--json"])
    assert rc_disp == 0
    out_disp = json.loads(capsys.readouterr().out)
    assert out_disp["ok"] is True
    assert out_disp["decision"] == "allow"
    assert out_disp["executed_slots"] == ["P10", "P20", "P30", "P40", "P50"]


def test_req005_cli_benchmark_under_10ms(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify 5-slot in-memory dispatch benchmark averages well under 10.0 ms."""
    from agy_golden_stack import cli

    rc_bench = cli.main(["benchmark", "--iterations", "20", "--json"])
    assert rc_bench == 0
    out_bench = json.loads(capsys.readouterr().out)
    assert out_bench["iterations"] == 20
    assert out_bench["avg_duration_ms"] < 10.0


def test_req005_repository_artifacts_and_5gate_hygiene() -> None:
    """Verify SKILL.md, plugin.json, hooks.json, LICENSE, and 100% English/PII-free repo."""
    skill_md = REPO_ROOT / ".agents" / "skills" / "agy-golden-stack" / "SKILL.md"
    plugin_json = REPO_ROOT / "plugins" / "agy-golden-stack" / "plugin.json"
    hooks_json = REPO_ROOT / "plugins" / "agy-golden-stack" / "hooks.json"
    rules_md = REPO_ROOT / "plugins" / "agy-golden-stack" / "rules" / "AGENTS.md"
    license_file = REPO_ROOT / "LICENSE"

    for required in (skill_md, plugin_json, hooks_json, rules_md, license_file):
        assert required.exists(), f"Missing required artifact: {required}"

    assert "MIT License" in license_file.read_text(encoding="utf-8")
    assert not rules_md.read_text(encoding="utf-8").startswith("---")

    forbidden = _forbidden_tokens()
    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", ".supergraph"}

    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not _has_cyrillic(text), f"Cyrillic character found in {path.relative_to(REPO_ROOT)}"
        for token in forbidden:
            assert token.lower() not in text.lower(), (
                f"Forbidden personal token found in {path.relative_to(REPO_ROOT)}"
            )
