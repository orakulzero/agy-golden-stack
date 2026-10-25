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
import math
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


def verify_v1_2_station_contracts(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate v1.2.0 peripheral station payload contracts.

    Supports:
    - pe_reversing_lab: syscall_stubs schema (name/symbol/ordinal, syscall_id/ssn, is_hooked/hooked).
    - eskd_vision_station: gost_2308 (geometric tolerances), gost_2309 (roughness), gost_2316 (notes).
    - agy_secret_shield: obfuscated_findings schema (encoding_type, decode_depth, rule_id, redacted_tag).
    - agy_federation_mesh: retry_history (attempt_count) and load_balancer (replica metrics).
    """
    if not isinstance(payload, dict):
        return {
            "valid": False,
            "checked_stations": [],
            "violations": ["Payload must be a dictionary"],
        }

    violations: List[str] = []
    checked_stations: Set[str] = set()

    # 1. pe_reversing_lab
    stubs = payload.get("syscall_stubs")
    pe_data = None
    if "pe_reversing_lab" in payload:
        pe_data = payload.get("pe_reversing_lab")
    elif "pe-reversing-lab" in payload:
        pe_data = payload.get("pe-reversing-lab")

    if pe_data is not None:
        checked_stations.add("pe_reversing_lab")
        if isinstance(pe_data, dict):
            if stubs is None:
                stubs = pe_data.get("syscall_stubs")
            if stubs is None:
                violations.append("pe_reversing_lab: payload missing required 'syscall_stubs' list")
        else:
            violations.append("pe_reversing_lab: station payload must be a dict")
    elif stubs is not None:
        checked_stations.add("pe_reversing_lab")

    if stubs is not None:
        if not isinstance(stubs, list):
            violations.append("pe_reversing_lab: syscall_stubs must be a list")
        else:
            for idx, stub in enumerate(stubs):
                if not isinstance(stub, dict):
                    violations.append(f"pe_reversing_lab: syscall_stub at index {idx} must be a dict")
                    continue
                if not any(k in stub for k in ("name", "symbol", "ordinal")):
                    violations.append(f"pe_reversing_lab: syscall_stub at index {idx} missing name, symbol, or ordinal")
                if not any(k in stub for k in ("syscall_id", "ssn")):
                    violations.append(f"pe_reversing_lab: syscall_stub at index {idx} missing syscall_id or ssn")
                else:
                    sid = stub.get("syscall_id") if "syscall_id" in stub else stub.get("ssn")
                    if not isinstance(sid, int) or isinstance(sid, bool) or sid < 0:
                        violations.append(f"pe_reversing_lab: syscall_stub at index {idx} syscall_id/ssn must be non-negative integer")
                if not any(k in stub for k in ("is_hooked", "hooked")):
                    violations.append(f"pe_reversing_lab: syscall_stub at index {idx} missing is_hooked or hooked flag")
                else:
                    hook = stub.get("is_hooked") if "is_hooked" in stub else stub.get("hooked")
                    if not isinstance(hook, bool):
                        violations.append(f"pe_reversing_lab: syscall_stub at index {idx} is_hooked/hooked must be a boolean")

    # 2. eskd_vision_station
    eskd_data = None
    if "eskd_vision_station" in payload:
        eskd_data = payload.get("eskd_vision_station")
    elif "eskd-vision-station" in payload:
        eskd_data = payload.get("eskd-vision-station")

    gost_2308 = payload.get("gost_2308")
    gost_2309 = payload.get("gost_2309")
    gost_2316 = payload.get("gost_2316")

    if eskd_data is not None:
        checked_stations.add("eskd_vision_station")
        if isinstance(eskd_data, dict):
            gost_2308 = gost_2308 if gost_2308 is not None else eskd_data.get("gost_2308")
            gost_2309 = gost_2309 if gost_2309 is not None else eskd_data.get("gost_2309")
            gost_2316 = gost_2316 if gost_2316 is not None else eskd_data.get("gost_2316")
            if gost_2308 is None and gost_2309 is None and gost_2316 is None:
                violations.append("eskd_vision_station: payload must contain at least one of gost_2308, gost_2309, or gost_2316")
        else:
            violations.append("eskd_vision_station: station payload must be a dict")
    elif any(g is not None for g in (gost_2308, gost_2309, gost_2316)):
        checked_stations.add("eskd_vision_station")

    if gost_2308 is not None:
        frames = None
        if isinstance(gost_2308, list):
            frames = gost_2308
        elif isinstance(gost_2308, dict):
            if "frames" in gost_2308 and isinstance(gost_2308["frames"], list):
                frames = gost_2308["frames"]
            elif "tolerances" in gost_2308 and isinstance(gost_2308["tolerances"], list):
                frames = gost_2308["tolerances"]
            elif "characteristic" in gost_2308:
                frames = [gost_2308]
            else:
                violations.append("eskd_vision_station: gost_2308 dict missing 'frames' or 'characteristic'")
        else:
            violations.append("eskd_vision_station: gost_2308 must be a list or dict")

        if frames is not None:
            for idx, frame in enumerate(frames):
                if not isinstance(frame, dict):
                    violations.append(f"eskd_vision_station: gost_2308 frame at index {idx} must be a dict")
                    continue
                if not frame.get("characteristic"):
                    violations.append(f"eskd_vision_station: gost_2308 frame at index {idx} missing characteristic")
                tol = frame.get("tolerance")
                if tol is None or not isinstance(tol, (int, float)) or tol <= 0:
                    violations.append(f"eskd_vision_station: gost_2308 frame at index {idx} tolerance must be positive number")

    if gost_2309 is not None:
        roughness_items = None
        if isinstance(gost_2309, list):
            roughness_items = gost_2309
        elif isinstance(gost_2309, dict):
            if "parameters" in gost_2309 and isinstance(gost_2309["parameters"], list):
                roughness_items = gost_2309["parameters"]
            elif any(k in gost_2309 for k in ("parameter", "value", "ra", "rz", "rmax")):
                roughness_items = [gost_2309]
            else:
                violations.append("eskd_vision_station: gost_2309 dict missing roughness parameters or values")
        else:
            violations.append("eskd_vision_station: gost_2309 must be a list or dict")

        if roughness_items is not None:
            for idx, item in enumerate(roughness_items):
                if not isinstance(item, dict):
                    violations.append(f"eskd_vision_station: gost_2309 item at index {idx} must be a dict")
                    continue
                val = item.get("value")
                if val is None:
                    for k in ("ra", "rz", "rmax"):
                        if k in item:
                            val = item[k]
                            break
                if val is None or not isinstance(val, (int, float)) or val <= 0:
                    violations.append(f"eskd_vision_station: gost_2309 item at index {idx} missing positive roughness value")

    if gost_2316 is not None:
        if isinstance(gost_2316, list):
            for idx, req in enumerate(gost_2316):
                if not isinstance(req, str) or not req.strip():
                    violations.append(f"eskd_vision_station: gost_2316 requirement note at index {idx} must be non-empty string")
        elif isinstance(gost_2316, dict):
            has_items = "items" in gost_2316 and isinstance(gost_2316["items"], list)
            has_text = "text" in gost_2316 and isinstance(gost_2316["text"], str)
            has_bbox = "tech_req_bbox" in gost_2316
            if not (has_items or has_text or has_bbox):
                violations.append("eskd_vision_station: gost_2316 dict must contain 'items', 'text', or 'tech_req_bbox'")
            if has_bbox:
                bbox = gost_2316["tech_req_bbox"]
                if not (isinstance(bbox, (list, tuple)) and len(bbox) == 4 and all(isinstance(c, (int, float)) and 0.0 <= c <= 1.0 for c in bbox)):
                    violations.append("eskd_vision_station: gost_2316 tech_req_bbox must be 4 coordinates in [0.0, 1.0]")
        elif isinstance(gost_2316, str):
            if not gost_2316.strip():
                violations.append("eskd_vision_station: gost_2316 text cannot be empty")
        else:
            violations.append("eskd_vision_station: gost_2316 must be a list, dict, or string")

    # 3. agy_secret_shield
    shield_data = None
    if "agy_secret_shield" in payload:
        shield_data = payload.get("agy_secret_shield")
    elif "agy-secret-shield" in payload:
        shield_data = payload.get("agy-secret-shield")

    findings = payload.get("obfuscated_findings")
    if shield_data is not None:
        checked_stations.add("agy_secret_shield")
        if isinstance(shield_data, dict):
            if findings is None:
                findings = shield_data.get("obfuscated_findings")
            if findings is None:
                violations.append("agy_secret_shield: payload missing required 'obfuscated_findings' list")
        else:
            violations.append("agy_secret_shield: station payload must be a dict")
    elif findings is not None:
        checked_stations.add("agy_secret_shield")

    if findings is not None:
        if not isinstance(findings, list):
            violations.append("agy_secret_shield: obfuscated_findings must be a list")
        else:
            for idx, item in enumerate(findings):
                if not isinstance(item, dict):
                    violations.append(f"agy_secret_shield: obfuscated_finding at index {idx} must be a dict")
                    continue
                enc = item.get("encoding_type")
                if not isinstance(enc, str) or not enc.strip():
                    violations.append(f"agy_secret_shield: item {idx} missing valid encoding_type")
                depth = item.get("decode_depth")
                if not isinstance(depth, int) or depth < 1:
                    violations.append(f"agy_secret_shield: item {idx} decode_depth must be integer >= 1")
                rule = item.get("rule_id")
                if not isinstance(rule, str) or not rule.strip():
                    violations.append(f"agy_secret_shield: item {idx} missing valid rule_id")
                tag = item.get("redacted_tag")
                if not isinstance(tag, str) or not tag.strip():
                    violations.append(f"agy_secret_shield: item {idx} missing valid redacted_tag")

    # 4. agy_federation_mesh
    fed_data = None
    if "agy_federation_mesh" in payload:
        fed_data = payload.get("agy_federation_mesh")
    elif "agy-federation-mesh" in payload:
        fed_data = payload.get("agy-federation-mesh")

    retries = payload.get("retry_history")
    lb = payload.get("load_balancer")

    if fed_data is not None:
        checked_stations.add("agy_federation_mesh")
        if isinstance(fed_data, dict):
            retries = retries if retries is not None else fed_data.get("retry_history")
            lb = lb if lb is not None else fed_data.get("load_balancer")
            if retries is None and lb is None:
                violations.append("agy_federation_mesh: payload must contain retry_history or load_balancer")
        else:
            violations.append("agy_federation_mesh: station payload must be a dict")
    elif retries is not None or lb is not None:
        checked_stations.add("agy_federation_mesh")

    if retries is not None:
        if not isinstance(retries, list):
            violations.append("agy_federation_mesh: retry_history must be a list")
        else:
            for idx, item in enumerate(retries):
                if not isinstance(item, dict):
                    violations.append(f"agy_federation_mesh: retry item at index {idx} must be a dict")
                    continue
                att = item.get("attempt_count") if "attempt_count" in item else item.get("attempt")
                if att is None or not isinstance(att, int) or isinstance(att, bool) or att < 0:
                    violations.append(f"agy_federation_mesh: retry item at index {idx} must have non-negative integer attempt_count or attempt")
                if "delay_ms" in item or "delay" in item:
                    del_val = item.get("delay_ms") if "delay_ms" in item else item.get("delay")
                    if (
                        del_val is None
                        or not isinstance(del_val, (int, float))
                        or isinstance(del_val, bool)
                        or (isinstance(del_val, float) and math.isnan(del_val))
                        or del_val < 0
                    ):
                        violations.append(f"agy_federation_mesh: retry item at index {idx} delay must be non-negative number")

    if lb is not None:
        if not isinstance(lb, dict):
            violations.append("agy_federation_mesh: load_balancer must be a dict")
        else:
            valid_keys = {"replicas", "latency_ema_ms", "weight", "status", "station_id", "inflight_count", "algorithm"}
            if not any(k in lb for k in valid_keys):
                violations.append("agy_federation_mesh: load_balancer missing replica metrics or 'replicas' list")
            if "replicas" in lb and not isinstance(lb["replicas"], list):
                violations.append("agy_federation_mesh: load_balancer replicas must be a list")

    return {
        "valid": len(violations) == 0,
        "checked_stations": sorted(list(checked_stations)),
        "violations": violations,
    }


def slot_p30_iso9000_gate(
    workspace_root: Path,
    event_name: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """P30: Enforce Agile V Self-Grading Bias role separation and validate v1.2 station contracts."""
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

    station_check = verify_v1_2_station_contracts(payload)
    if station_check["checked_stations"]:
        context["station_contracts_verification"] = station_check
        if not station_check["valid"]:
            role = str(payload.get("role") or "").lower().strip()
            if role in ("implementer", "build-agent", "station-agent") or bool(payload.get("enforce_station_contracts")):
                return {
                    "decision": "block",
                    "reason": "Station contract violation: " + "; ".join(station_check["violations"]),
                }

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
    """P50: Intercept `git push` or `gh release create` and enforce 5-Gate OSS Release Audit and station contracts."""
    station_check = verify_v1_2_station_contracts(payload)
    if station_check["checked_stations"]:
        context["station_contracts_verification"] = station_check
        if not station_check["valid"]:
            cmd = str(payload.get("command") or "").lower()
            tool_name = str(payload.get("tool_name") or "").lower()
            is_push_or_release = (
                (tool_name == "run_command" and any(k in cmd for k in ("git push", "gh release", "git tag")))
                or event_name in ("PrePush", "ReleaseAudit", "PreRelease")
                or bool(payload.get("is_release"))
                or bool(payload.get("enforce_station_contracts"))
            )
            if is_push_or_release:
                return {
                    "decision": "block",
                    "reason": "Station contract violation in release gate: " + "; ".join(station_check["violations"]),
                }

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
