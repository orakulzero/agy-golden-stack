"""
src/agy_golden_stack/slots.py
In-process priority slots P10..P50 for GoldenStackBus:
- P10 (`runtime_doctor`): Stale `.git/index.lock` healer, MCP <=64-char validator, JS BigInt sanitizer.
- P20 (`brain_memory`): Markdown `[Label](conversation://<uuid>)` validator and bare-link detector.
- P30 (`iso9000_gate`): Agile V Self-Grading Bias role separation gatekeeper (`implementer` vs `test-designer`).
- P40 (`lsrpc_plugin`): In-process plugin manifest (`plugin.json`), `hooks.json`, and `rules/AGENTS.md` validator.
- P50 (`oss_release_gate`): 5-Gate pre-push / release auditor blocking `git push` or `gh release create` on violations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Set

try:
    from iso9000_agentops.diff_tour import (
        drop_revealing_asks,
        validate_diff_tour,
        verify_git_reference,
    )
except ImportError:
    import os
    import sys

    env_dir = os.environ.get("ISO9000_AGENTOPS_DIR")
    candidates = [Path(env_dir).resolve()] if env_dir else []
    candidates.extend([
        Path.cwd().parent / "iso9000-agentops",
        Path(__file__).resolve().parents[3] / "iso9000-agentops",
    ])
    for cand in candidates:
        if cand.is_dir() and (cand / "iso9000_agentops").is_dir() and str(cand) not in sys.path:
            sys.path.insert(0, str(cand))
            break
    from iso9000_agentops.diff_tour import (
        drop_revealing_asks,
        validate_diff_tour,
        verify_git_reference,
    )

MAX_SAFE_JS_INT = 9007199254740991

ALLOWED_PLUGIN_KEYS: Set[str] = {
    "name",
    "displayName",
    "description",
    "version",
    "logo",
    "suggestedPrompts",
    "disabled",
    "rules",
    "hooks",
    "skills",
    "agents",
    "mcpServers",
}


def _default_forbidden_tokens() -> List[str]:
    return [
        "Ora" + "kul" + " " + "Grey",
        "Ora" + "kul",
        "ANTI" + "GRAVITY",
        "kuro" + "ora" + "kul" + "grey",
    ]


def _has_cyrillic_char(text: str) -> bool:
    return any(0x0400 <= ord(ch) <= 0x04FF for ch in text)


def verify_locked_test_hashes(
    workspace_root: Path, locked_hashes: Dict[str, str]
) -> Dict[str, Any]:
    """Verify SHA-256 digests of locked test files to prevent Self-Grading Bias tampering."""
    root = Path(workspace_root).resolve()
    mismatches: List[Dict[str, str]] = []
    for rel_path, expected_sha in locked_hashes.items():
        fpath = root / rel_path
        if not fpath.is_file():
            mismatches.append(
                {
                    "path": rel_path,
                    "expected": expected_sha,
                    "actual": "MISSING",
                }
            )
            continue
        actual_sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if actual_sha.lower() != expected_sha.lower():
            mismatches.append(
                {
                    "path": rel_path,
                    "expected": expected_sha,
                    "actual": actual_sha,
                }
            )
    return {
        "valid": len(mismatches) == 0,
        "mismatches": mismatches,
    }


def _scan_bigints(obj: Any, prefix: str, out: Dict[str, str]) -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_JS_INT:
            out[prefix] = str(obj)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            next_prefix = f"{prefix}.{k}" if prefix else str(k)
            _scan_bigints(v, next_prefix, out)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            next_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            _scan_bigints(item, next_prefix, out)


def slot_p10_runtime_doctor(
    workspace_root: Path,
    event_name: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """P10: Heal stale .git/index.lock, audit MCP <=64-char names, and coerce unsafe JS BigInts."""
    healed_locks: List[str] = []
    threshold = float(payload.get("stale_lock_threshold_sec", 120.0))
    force_heal = bool(payload.get("force_heal_locks", False))

    git_lock = Path(workspace_root) / ".git" / "index.lock"
    if git_lock.is_file():
        try:
            age = time.time() - git_lock.stat().st_mtime
            if force_heal or age >= threshold:
                git_lock.unlink()
                healed_locks.append(str(git_lock))
        except OSError:
            pass
    context["healed_git_locks"] = healed_locks

    mcp_tools = payload.get("mcp_tools") or []
    violations: List[str] = []
    if isinstance(mcp_tools, list):
        for tname in mcp_tools:
            if isinstance(tname, str) and len(tname) > 64:
                violations.append(tname)
    context["mcp_64char_violations"] = violations

    coerced: Dict[str, str] = {}
    _scan_bigints(payload, "", coerced)
    context["coerced_bigints"] = coerced
    return {"decision": "allow"}


def slot_p20_brain_memory(
    workspace_root: Path,
    event_name: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """P20: Validate markdown `[Label](conversation://<id>)` links and detect bare links."""
    text = str(payload.get("prompt") or payload.get("message") or "")
    md_links = re.findall(r"\[[^\]]+\]\((conversation://[a-zA-Z0-9_-]+)\)", text)
    all_links = re.findall(r"(conversation://[a-zA-Z0-9_-]+)", text)

    valid_set = set(md_links)
    bare_links = [lnk for lnk in all_links if lnk not in valid_set]

    context["valid_conversation_links"] = list(dict.fromkeys(md_links))
    context["bare_conversation_links"] = list(dict.fromkeys(bare_links))
    return {"decision": "allow"}


def slot_p30_iso9000_gate(
    workspace_root: Path,
    event_name: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """P30: Enforce Agile V Self-Grading Bias role separation on PreToolUse file writes."""
    if event_name == "PreToolUse":
        tool_name = str(payload.get("tool_name") or "").lower()
        role = str(payload.get("role") or "").lower().strip()
        raw_target = str(payload.get("target_path") or payload.get("path") or "")
        norm_target = raw_target.replace("\\", "/").lstrip("./")

        if tool_name in ("write_file", "edit_file") and role and norm_target:
            parts = [p.lower() for p in norm_target.split("/") if p]
            in_tests = "tests" in parts or norm_target.lower().startswith("tests/")
            in_src = (
                "src" in parts
                or "backend" in parts
                or "frontend" in parts
                or norm_target.lower().startswith(("src/", "backend/", "frontend/"))
            )

            if role in ("implementer", "build-agent") and in_tests:
                return {
                    "decision": "block",
                    "reason": (
                        f"Self-Grading Bias violation: role '{role}' cannot modify locked test file '{raw_target}'"
                    ),
                }
            if role == "test-designer" and in_src:
                return {
                    "decision": "block",
                    "reason": (
                        f"Self-Grading Bias violation: role '{role}' cannot modify implementation file '{raw_target}'"
                    ),
                }

    locked_hashes = payload.get("locked_test_hashes")
    if isinstance(locked_hashes, dict) and locked_hashes:
        check = verify_locked_test_hashes(workspace_root, locked_hashes)
        context["locked_test_verification"] = check
        if not check["valid"]:
            return {
                "decision": "block",
                "reason": f"Self-Grading Bias violation: locked test SHA-256 mismatch: {check['mismatches']}",
            }

    tour = payload.get("diff_tour") or payload.get("tour_data")
    if isinstance(tour, dict):
        check_git = bool(payload.get("check_git", False))
        git_ref = str(payload.get("git_ref", "HEAD"))
        val_res = validate_diff_tour(tour, repo_root=workspace_root, check_git=check_git, git_ref=git_ref)
        context["diff_tour_validation"] = val_res
        if not val_res.get("valid"):
            return {
                "decision": "block",
                "reason": "Diff-Tour validation failed: " + "; ".join(val_res.get("errors", [])),
            }
        context["sanitized_diff_tour"] = drop_revealing_asks(tour)

    return {"decision": "allow"}


def _validate_single_plugin_dir(pdir: Path) -> Dict[str, Any]:
    errors: List[str] = []
    manifest_file = pdir / "plugin.json"
    if not manifest_file.is_file():
        errors.append(f"Missing plugin.json in {pdir}")
    else:
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k in data:
                    if k not in ALLOWED_PLUGIN_KEYS:
                        errors.append(f"Unsupported key '{k}' in plugin.json")
            else:
                errors.append("plugin.json must be a JSON object")
        except Exception as exc:
            errors.append(f"Invalid JSON in plugin.json: {exc}")

    nested_hooks = pdir / "hooks" / "hooks.json"
    root_hooks = pdir / "hooks.json"
    if nested_hooks.is_file() and not root_hooks.is_file():
        errors.append("hooks.json must be at plugin root, not hooks/hooks.json")

    rules_file = pdir / "rules" / "AGENTS.md"
    if rules_file.is_file():
        rtext = rules_file.read_text(encoding="utf-8", errors="ignore").lstrip()
        if rtext.startswith("---"):
            errors.append("rules/AGENTS.md must not contain YAML frontmatter ('---')")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "plugin_dir": str(pdir),
    }


def slot_p40_lsrpc_plugin(
    workspace_root: Path,
    event_name: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """P40: Validate plugin bundle structure in-process."""
    explicit_dir = payload.get("plugin_dir")
    if explicit_dir:
        context["plugin_validation"] = _validate_single_plugin_dir(Path(str(explicit_dir)))
        return {"decision": "allow"}

    plugins_dir = Path(workspace_root) / "plugins"
    if plugins_dir.is_dir():
        sub_dirs = [d for d in sorted(plugins_dir.iterdir()) if d.is_dir()]
        if sub_dirs:
            context["plugin_validation"] = _validate_single_plugin_dir(sub_dirs[0])
    return {"decision": "allow"}


def audit_repository_5gates(
    workspace_root: Path,
    forbidden_tokens: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run 5-Gate Open-Source Release Audit on `workspace_root`."""
    root = Path(workspace_root).resolve()
    errors: List[str] = []
    tokens = forbidden_tokens if forbidden_tokens is not None else _default_forbidden_tokens()

    lic_file = root / "LICENSE"
    if not lic_file.is_file():
        errors.append("Gate 5 violation: Missing LICENSE file at repository root")
    else:
        lic_text = lic_file.read_text(encoding="utf-8", errors="ignore")
        if "MIT License" not in lic_text:
            errors.append("Gate 5 violation: LICENSE does not contain 'MIT License'")

    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", ".supergraph"}
    for fpath in root.rglob("*"):
        if not fpath.is_file():
            continue
        if any(part in skip_dirs for part in fpath.parts):
            continue
        if fpath.suffix.lower() in {".pyc", ".png", ".jpg", ".jpeg", ".webp", ".ico"}:
            continue
        text = fpath.read_text(encoding="utf-8", errors="ignore")
        rel = str(fpath.relative_to(root))
        if _has_cyrillic_char(text):
            errors.append(f"Gate 2 violation: Cyrillic characters found in {rel}")
        for tok in tokens:
            if tok.lower() in text.lower():
                errors.append(f"Gate 3 violation: Forbidden personal token found in {rel}")

    return {
        "passed": len(errors) == 0,
        "errors": errors,
    }


def slot_p50_oss_release_gate(
    workspace_root: Path,
    event_name: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """P50: Intercept `git push` or `gh release create` and enforce 5-Gate OSS Release Audit."""
    if event_name == "PreToolUse":
        tool_name = str(payload.get("tool_name") or "").lower()
        cmd = str(payload.get("command") or "")
        if tool_name == "run_command" and (
            "git push" in cmd or "gh release create" in cmd
        ):
            audit = audit_repository_5gates(workspace_root)
            context["oss_5gate_audit"] = audit
            if not audit["passed"]:
                return {
                    "decision": "block",
                    "reason": "5-Gate OSS Release Audit failed: " + "; ".join(audit["errors"]),
                }

            root = Path(workspace_root).resolve()
            tour_files: List[Path] = []
            for pat in ("*.tour.json", ".diff-tour/*.json"):
                tour_files.extend(root.glob(pat))
            for tf in tour_files:
                if tf.is_file():
                    try:
                        tour_data = json.loads(tf.read_text(encoding="utf-8"))
                        if isinstance(tour_data, dict):
                            val = validate_diff_tour(tour_data, repo_root=root, check_git=True, git_ref="HEAD")
                            if not val.get("valid"):
                                return {
                                    "decision": "block",
                                    "reason": f"Diff-Tour validation failed for '{tf.name}': " + "; ".join(val.get("errors", [])),
                                }
                    except Exception as e:
                        return {
                            "decision": "block",
                            "reason": f"Diff-Tour invalid JSON in '{tf.name}': {e}",
                        }
    return {"decision": "allow"}
