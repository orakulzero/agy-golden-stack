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

import copy
import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

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
                if any(k in pe_data for k in ("imphash", "rich_header", "cfg_summary", "security_and_unwind")):
                    checked_stations.discard("pe_reversing_lab")
                else:
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
                if any(k in eskd_data for k in ("vector_line_weights", "gost_2106_bom", "gost_2307_dimensions", "gost_2302_scale")):
                    checked_stations.discard("eskd_vision_station")
                else:
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
                if any(k in shield_data for k in ("ast_taint_findings", "ast_secrets", "secret_scan_sarif")):
                    checked_stations.discard("agy_secret_shield")
                else:
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
                if any(k in fed_data for k in ("pareto_frontier", "byzantine_quorum_consensus", "work_stealing_scheduler")):
                    checked_stations.discard("agy_federation_mesh")
                else:
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


def verify_v1_3_station_contracts(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate v1.3.0 peripheral station payload contracts.

    Supports:
    - pe_reversing_lab: imphash (32-character hexadecimal MD5), rich_header (dan_s_present bool, entries list),
      cfg_summary (block_count >= 1, cyclomatic_complexity >= 1).
    - agy_secret_shield: ast_taint_findings (category in {"live_assignment", "taint_concatenation", "env_fallback", "api_client_arg"},
      line_number >= 1, confidence in {"HIGH", "MEDIUM", "LOW"}).
    - eskd_vision_station: vector_line_weights (main_stroke_mm in [0.5, 1.4], thin_stroke_mm > 0, ratio in [0.3, 0.55]),
      gost_2106_bom (7 standard columns, rows with pos >= 1).
    - agy_federation_mesh: pareto_frontier (worker_id, latency_p50 > 0, cost >= 0, reliability in [0.0, 1.0]).
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
    pe_data = None
    if "pe_reversing_lab" in payload:
        pe_data = payload.get("pe_reversing_lab")
    elif "pe-reversing-lab" in payload:
        pe_data = payload.get("pe-reversing-lab")
    elif any(k in payload for k in ("imphash", "rich_header", "cfg_summary")):
        pe_data = payload

    if pe_data is not None:
        checked_stations.add("pe_reversing_lab")
        if not isinstance(pe_data, dict):
            violations.append("pe_reversing_lab: station payload must be a dict")
        else:
            imphash = pe_data.get("imphash")
            rich_header = pe_data.get("rich_header")
            cfg_summary = pe_data.get("cfg_summary") if "cfg_summary" in pe_data else pe_data.get("basic_blocks")

            if imphash is None and rich_header is None and cfg_summary is None:
                if any(k in pe_data for k in ("syscall_stubs", "security_and_unwind")):
                    checked_stations.discard("pe_reversing_lab")
                else:
                    violations.append("pe_reversing_lab: payload missing required v1.3.0 telemetry (imphash, rich_header, cfg_summary)")

            if imphash is not None:
                if not (isinstance(imphash, str) and len(imphash) == 32 and all(c in "0123456789abcdefABCDEF" for c in imphash)):
                    violations.append("pe_reversing_lab: imphash must be a 32-character hexadecimal MD5 hash")

            if rich_header is not None:
                if not isinstance(rich_header, dict):
                    violations.append("pe_reversing_lab: rich_header must be a dict")
                else:
                    if "dan_s_present" in rich_header and not isinstance(rich_header["dan_s_present"], bool):
                        violations.append("pe_reversing_lab: rich_header dan_s_present must be a boolean")
                    if "entries" in rich_header and not isinstance(rich_header["entries"], list):
                        violations.append("pe_reversing_lab: rich_header entries must be a list")

            if cfg_summary is not None:
                if not isinstance(cfg_summary, dict):
                    violations.append("pe_reversing_lab: cfg_summary must be a dict")
                else:
                    bc = cfg_summary.get("block_count")
                    if bc is None or not isinstance(bc, int) or isinstance(bc, bool) or bc < 1:
                        violations.append("pe_reversing_lab: cfg_summary block_count must be integer >= 1")
                    cc = cfg_summary.get("cyclomatic_complexity")
                    if cc is None or not isinstance(cc, int) or isinstance(cc, bool) or cc < 1:
                        violations.append("pe_reversing_lab: cfg_summary cyclomatic_complexity must be integer >= 1")

    # 2. agy_secret_shield
    shield_data = None
    if "agy_secret_shield" in payload:
        shield_data = payload.get("agy_secret_shield")
    elif "agy-secret-shield" in payload:
        shield_data = payload.get("agy-secret-shield")
    elif any(k in payload for k in ("ast_taint_findings", "ast_secrets")):
        shield_data = payload

    if shield_data is not None:
        checked_stations.add("agy_secret_shield")
        if not isinstance(shield_data, dict):
            violations.append("agy_secret_shield: station payload must be a dict")
        else:
            findings = shield_data.get("ast_taint_findings") if "ast_taint_findings" in shield_data else shield_data.get("ast_secrets")
            if findings is None:
                if any(k in shield_data for k in ("obfuscated_findings", "secret_scan_sarif")):
                    checked_stations.discard("agy_secret_shield")
                else:
                    violations.append("agy_secret_shield: payload missing required 'ast_taint_findings' list")
            elif not isinstance(findings, list):
                violations.append("agy_secret_shield: ast_taint_findings must be a list")
            else:
                valid_cats = {"live_assignment", "taint_concatenation", "env_fallback", "api_client_arg"}
                valid_confs = {"HIGH", "MEDIUM", "LOW"}
                for idx, item in enumerate(findings):
                    if not isinstance(item, dict):
                        violations.append(f"agy_secret_shield: finding at index {idx} must be a dict")
                        continue
                    cat = item.get("category")
                    if cat not in valid_cats:
                        violations.append(f"agy_secret_shield: finding at index {idx} invalid category '{cat}'")
                    lineno = item.get("line_number")
                    if lineno is None or not isinstance(lineno, int) or isinstance(lineno, bool) or lineno < 1:
                        violations.append(f"agy_secret_shield: finding at index {idx} line_number must be integer >= 1")
                    conf = item.get("confidence")
                    if conf not in valid_confs:
                        violations.append(f"agy_secret_shield: finding at index {idx} invalid confidence '{conf}'")

    # 3. eskd_vision_station
    eskd_data = None
    if "eskd_vision_station" in payload:
        eskd_data = payload.get("eskd_vision_station")
    elif "eskd-vision-station" in payload:
        eskd_data = payload.get("eskd-vision-station")
    elif any(k in payload for k in ("vector_line_weights", "gost_2106_bom")):
        eskd_data = payload

    if eskd_data is not None:
        checked_stations.add("eskd_vision_station")
        if not isinstance(eskd_data, dict):
            violations.append("eskd_vision_station: station payload must be a dict")
        else:
            weights = eskd_data.get("vector_line_weights")
            bom = eskd_data.get("gost_2106_bom")
            if weights is None and bom is None:
                if any(k in eskd_data for k in ("gost_2308", "gost_2309", "gost_2316", "gost_2307_dimensions", "gost_2302_scale")):
                    checked_stations.discard("eskd_vision_station")
                else:
                    violations.append("eskd_vision_station: payload missing required vector_line_weights or gost_2106_bom")

            if weights is not None:
                if not isinstance(weights, dict):
                    violations.append("eskd_vision_station: vector_line_weights must be a dict")
                else:
                    main_s = weights.get("main_stroke_mm")
                    if main_s is None or not isinstance(main_s, (int, float)) or isinstance(main_s, bool) or not (0.5 <= main_s <= 1.4):
                        violations.append("eskd_vision_station: vector_line_weights main_stroke_mm must be in range [0.5, 1.4]")
                    thin_s = weights.get("thin_stroke_mm")
                    if thin_s is None or not isinstance(thin_s, (int, float)) or isinstance(thin_s, bool) or thin_s <= 0:
                        violations.append("eskd_vision_station: vector_line_weights thin_stroke_mm must be positive number")
                    ratio = weights.get("ratio")
                    if ratio is None or not isinstance(ratio, (int, float)) or isinstance(ratio, bool) or not (0.3 <= ratio <= 0.55):
                        violations.append("eskd_vision_station: vector_line_weights ratio must be in range [0.3, 0.55]")

            if bom is not None:
                if not isinstance(bom, dict):
                    violations.append("eskd_vision_station: gost_2106_bom must be a dict")
                else:
                    cols = bom.get("columns")
                    if not isinstance(cols, list) or len(cols) != 7:
                        violations.append("eskd_vision_station: gost_2106_bom must contain exactly 7 standard columns")
                    rows = bom.get("rows")
                    if not isinstance(rows, list):
                        violations.append("eskd_vision_station: gost_2106_bom rows must be a list")
                    else:
                        for idx, row in enumerate(rows):
                            if not isinstance(row, dict):
                                violations.append(f"eskd_vision_station: BOM row at index {idx} must be a dict")
                            else:
                                pos = row.get("pos")
                                if pos is not None and (not isinstance(pos, int) or isinstance(pos, bool) or pos < 1):
                                    violations.append(f"eskd_vision_station: BOM row at index {idx} pos must be integer >= 1")

    # 4. agy_federation_mesh
    fed_data = None
    if "agy_federation_mesh" in payload:
        fed_data = payload.get("agy_federation_mesh")
    elif "agy-federation-mesh" in payload:
        fed_data = payload.get("agy-federation-mesh")
    elif "pareto_frontier" in payload:
        fed_data = payload

    if fed_data is not None:
        checked_stations.add("agy_federation_mesh")
        if not isinstance(fed_data, dict):
            violations.append("agy_federation_mesh: station payload must be a dict")
        else:
            pareto = fed_data.get("pareto_frontier")
            if pareto is None:
                if any(k in fed_data for k in ("retry_history", "load_balancer", "attempt_count", "byzantine_quorum_consensus", "work_stealing_scheduler")):
                    checked_stations.discard("agy_federation_mesh")
                else:
                    violations.append("agy_federation_mesh: payload missing required pareto_frontier list")
            elif not isinstance(pareto, list):
                violations.append("agy_federation_mesh: pareto_frontier must be a list")
            else:
                for idx, worker in enumerate(pareto):
                    if not isinstance(worker, dict):
                        violations.append(f"agy_federation_mesh: pareto worker at index {idx} must be a dict")
                        continue
                    wid = worker.get("worker_id")
                    if not isinstance(wid, str) or not wid.strip():
                        violations.append(f"agy_federation_mesh: pareto worker at index {idx} missing valid worker_id")
                    lat = worker.get("latency_p50")
                    if lat is None or not isinstance(lat, (int, float)) or isinstance(lat, bool) or lat <= 0:
                        violations.append(f"agy_federation_mesh: pareto worker at index {idx} latency_p50 must be positive float")
                    cost = worker.get("cost")
                    if cost is None or not isinstance(cost, (int, float)) or isinstance(cost, bool) or cost < 0:
                        violations.append(f"agy_federation_mesh: pareto worker at index {idx} cost must be non-negative float")
                    rel = worker.get("reliability")
                    if rel is None or not isinstance(rel, (int, float)) or isinstance(rel, bool) or not (0.0 <= rel <= 1.0):
                        violations.append(f"agy_federation_mesh: pareto worker at index {idx} reliability must be in range [0.0, 1.0]")

    return {
        "valid": len(violations) == 0,
        "checked_stations": sorted(list(checked_stations)),
        "violations": violations,
    }


def inspect_computer_use_bus_event(
    event_type: str,
    payload: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Inspect computer-use action and event payloads for visual safety, bounds, and prompt injection (REQ-GS-201)."""
    if not isinstance(payload, dict):
        return {
            "allowed": False,
            "decision": "block",
            "reason": "Payload must be a dictionary",
            "safety_flags": ["INVALID_PAYLOAD"],
            "sanitized_payload": None,
        }

    safety_flags: List[str] = []
    reasons: List[str] = []
    sanitized = copy.deepcopy(payload)

    # 1. Coordinate Boundary Enforcement
    coords_to_check: List[Tuple[str, float]] = []
    if "norm_x" in payload and isinstance(payload["norm_x"], (int, float)) and not isinstance(payload["norm_x"], bool):
        coords_to_check.append(("norm_x", float(payload["norm_x"])))
    if "norm_y" in payload and isinstance(payload["norm_y"], (int, float)) and not isinstance(payload["norm_y"], bool):
        coords_to_check.append(("norm_y", float(payload["norm_y"])))

    for k in ("coordinates", "point", "coords"):
        val = payload.get(k)
        if isinstance(val, (list, tuple)) and len(val) >= 2:
            if isinstance(val[0], (int, float)) and not isinstance(val[0], bool):
                coords_to_check.append((f"{k}[0]", float(val[0])))
            if isinstance(val[1], (int, float)) and not isinstance(val[1], bool):
                coords_to_check.append((f"{k}[1]", float(val[1])))

    for name, c in coords_to_check:
        if c < 0.0 or c > 1000.0:
            safety_flags.append("OUT_OF_BOUNDS")
            reasons.append(f"Coordinate {name}={c} out of bounds [0, 1000]")
            break

    # 2. Prompt-Injection Sanitization & Zero-width detection
    zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u202a", "\u202e"]
    injection_patterns = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions", re.IGNORECASE),
        re.compile(r"system\s+override", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"execute_arbitrary", re.IGNORECASE),
        re.compile(r"disable\s+visual\s+safety", re.IGNORECASE),
    ]

    def _scan_and_sanitize(obj: Any) -> Any:
        if isinstance(obj, str):
            for pat in injection_patterns:
                if pat.search(obj):
                    if "PROMPT_INJECTION" not in safety_flags:
                        safety_flags.append("PROMPT_INJECTION")
                    reasons.append(f"Prompt injection pattern detected: '{pat.pattern}'")
                    break

            cleaned = obj
            has_zw = any(zw in cleaned for zw in zero_width_chars)
            if has_zw:
                for zw in zero_width_chars:
                    cleaned = cleaned.replace(zw, "")
                if any(k in cleaned.lower() for k in ("execute", "shell", "secret", "override", "system")):
                    if "PROMPT_INJECTION" not in safety_flags:
                        safety_flags.append("PROMPT_INJECTION")
                    reasons.append("Zero-width hidden command detected")
                return cleaned
            return obj
        elif isinstance(obj, dict):
            return {k: _scan_and_sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_scan_and_sanitize(item) for item in obj]
        return obj

    sanitized = _scan_and_sanitize(sanitized)

    # 3. Visual Oracle Gate
    action = str(payload.get("action") or payload.get("action_type") or "").lower()
    mutating_actions = {"click", "double_click", "triple_click", "middle_click", "right_click", "press", "key", "type", "drag", "write"}
    receipt = payload.get("visual_change_receipt") or payload.get("visual_receipt")
    if action in mutating_actions and receipt is None:
        safety_flags.append("MISSING_VISUAL_ORACLE")

    allowed = len(reasons) == 0
    decision = "allow" if allowed else "block"
    reason = "; ".join(reasons) if reasons else None

    return {
        "allowed": allowed,
        "decision": decision,
        "reason": reason,
        "sanitized_payload": sanitized,
        "safety_flags": safety_flags,
    }


def verify_v2_0_station_contracts(payload: Optional[Dict[str, Any]] = None, stations: Optional[Any] = None) -> Dict[str, Any]:
    """Validate Antigravity v2.0.0 ecosystem station payload contracts across all 10 non-video stations (REQ-GS-202)."""
    data = payload if payload is not None else (stations if isinstance(stations, dict) else {})
    if not isinstance(data, dict):
        return {
            "valid": False,
            "checked_stations": [],
            "violations": ["Payload must be a dictionary"],
        }

    violations: List[str] = []
    checked_stations: Set[str] = set()

    # 1. iso9000_agentops
    iso_data = data.get("iso9000_agentops") or data.get("iso9000-agentops")
    if iso_data is not None:
        checked_stations.add("iso9000_agentops")
        if not isinstance(iso_data, dict):
            violations.append("iso9000_agentops: station payload must be a dict")
        else:
            soa = iso_data.get("soa")
            if soa is not None and isinstance(soa, dict):
                count = soa.get("controls_implemented_count")
                min_req = soa.get("mandatory_minimum", 20)
                if count is None or not isinstance(count, int) or count < min_req or count < 20:
                    violations.append(f"iso9000_agentops: ISO/IEC 42001 soa controls_implemented_count ({count}) must be >= {min_req}")
            cert = iso_data.get("portfolio_certificate")
            if cert is not None and isinstance(cert, dict):
                cov = cert.get("mean_rtm_coverage")
                if cov is not None and (not isinstance(cov, (int, float)) or cov < 0.0 or cov > 1.0):
                    violations.append("iso9000_agentops: portfolio_certificate mean_rtm_coverage must be in [0.0, 1.0]")

    # 2. agy_computer_use
    cua_data = data.get("agy_computer_use") or data.get("agy-computer-use")
    if cua_data is not None:
        checked_stations.add("agy_computer_use")
        if not isinstance(cua_data, dict):
            violations.append("agy_computer_use: station payload must be a dict")
        else:
            anchor = cua_data.get("visual_anchor")
            if anchor is not None and isinstance(anchor, dict):
                score = anchor.get("match_score")
                if score is not None and (not isinstance(score, (int, float)) or isinstance(score, bool) or score < 0.0 or score > 1.0):
                    violations.append(f"agy_computer_use: visual_anchor match_score ({score}) must be in range [0.0, 1.0]")
            traj = cua_data.get("recorded_trajectory")
            if traj is not None and isinstance(traj, dict):
                if "steps" in traj and not isinstance(traj["steps"], list):
                    violations.append("agy_computer_use: recorded_trajectory steps must be a list")

    # 3. agy_golden_stack
    gs_data = data.get("agy_golden_stack") or data.get("agy-golden-stack")
    if gs_data is not None:
        checked_stations.add("agy_golden_stack")
        if not isinstance(gs_data, dict):
            violations.append("agy_golden_stack: station payload must be a dict")
        else:
            telemetry = gs_data.get("bus_telemetry")
            if telemetry is not None and isinstance(telemetry, dict):
                p95 = telemetry.get("sla_p95_ms")
                max_p95 = telemetry.get("max_allowed_sla_p95_ms", 1.0)
                if p95 is not None and (not isinstance(p95, (int, float)) or p95 > max_p95):
                    violations.append(f"agy_golden_stack: bus_telemetry sla_p95_ms ({p95}) exceeds max allowed ({max_p95})")

    # 4. agy_brain_memory
    bm_data = data.get("agy_brain_memory") or data.get("agy-brain-memory")
    if bm_data is not None:
        checked_stations.add("agy_brain_memory")
        if not isinstance(bm_data, dict):
            violations.append("agy_brain_memory: station payload must be a dict")
        else:
            budget = bm_data.get("context_budget_allocation")
            if budget is not None and isinstance(budget, dict):
                alloc = budget.get("allocated_tokens")
                max_b = budget.get("max_budget")
                if alloc is not None and max_b is not None and alloc > max_b:
                    violations.append(f"agy_brain_memory: context_budget_allocation allocated_tokens ({alloc}) exceeds max_budget ({max_b})")

    # 5. agy_doctor_mux
    dm_data = data.get("agy_doctor_mux") or data.get("agy-doctor-mux")
    if dm_data is not None:
        checked_stations.add("agy_doctor_mux")
        if not isinstance(dm_data, dict):
            violations.append("agy_doctor_mux: station payload must be a dict")
        else:
            matrix = dm_data.get("ecosystem_version_matrix")
            if matrix is not None and isinstance(matrix, dict):
                target_ver = matrix.get("target_version")
                if target_ver != "2.0.0":
                    violations.append(f"agy_doctor_mux: ecosystem_version_matrix target_version must be '2.0.0', got '{target_ver}'")

    # 6. agy_lsrpc_bridge
    lb_data = data.get("agy_lsrpc_bridge") or data.get("agy-lsrpc-bridge")
    if lb_data is not None:
        checked_stations.add("agy_lsrpc_bridge")
        if not isinstance(lb_data, dict):
            violations.append("agy_lsrpc_bridge: station payload must be a dict")
        else:
            coll = lb_data.get("cross_plugin_mcp_collisions")
            if coll is not None and isinstance(coll, dict):
                tokens = coll.get("fleet_estimated_tokens", 0)
                budget_tok = coll.get("fleet_token_budget", 16000)
                if coll.get("has_collisions") is True:
                    violations.append("agy_lsrpc_bridge: cross_plugin_mcp_collisions detected collisions")
                if coll.get("within_fleet_budget") is False or tokens > budget_tok:
                    violations.append(f"agy_lsrpc_bridge: fleet_estimated_tokens ({tokens}) exceeds budget ({budget_tok})")

    # 7. pe_reversing_lab
    pe_data = data.get("pe_reversing_lab") or data.get("pe-reversing-lab")
    if pe_data is not None:
        checked_stations.add("pe_reversing_lab")
        if not isinstance(pe_data, dict):
            violations.append("pe_reversing_lab: station payload must be a dict")
        else:
            sec = pe_data.get("security_and_unwind")
            if sec is not None and isinstance(sec, dict):
                if "export_forwarders_count" in sec and sec["export_forwarders_count"] < 0:
                    violations.append("pe_reversing_lab: export_forwarders_count must be non-negative")
                if "pdata_unwind_records" in sec and sec["pdata_unwind_records"] < 0:
                    violations.append("pe_reversing_lab: pdata_unwind_records must be non-negative")

    # 8. eskd_vision_station
    eskd_data = data.get("eskd_vision_station") or data.get("eskd-vision-station")
    if eskd_data is not None:
        checked_stations.add("eskd_vision_station")
        if not isinstance(eskd_data, dict):
            violations.append("eskd_vision_station: station payload must be a dict")
        else:
            dims = eskd_data.get("gost_2307_dimensions")
            if dims is not None and isinstance(dims, dict):
                if dims.get("valid") is False:
                    violations.append("eskd_vision_station: gost_2307_dimensions is invalid")
            scale = eskd_data.get("gost_2302_scale")
            if scale is not None and isinstance(scale, dict):
                if scale.get("standard_compliant") is False:
                    violations.append("eskd_vision_station: gost_2302_scale is not standard compliant")

    # 9. agy_secret_shield
    ss_data = data.get("agy_secret_shield") or data.get("agy-secret-shield")
    if ss_data is not None:
        checked_stations.add("agy_secret_shield")
        if not isinstance(ss_data, dict):
            violations.append("agy_secret_shield: station payload must be a dict")
        else:
            sarif = ss_data.get("secret_scan_sarif")
            if sarif is not None and isinstance(sarif, dict):
                ver = sarif.get("version")
                if ver != "2.1.0":
                    violations.append(f"agy_secret_shield: secret_scan_sarif version must be '2.1.0', got '{ver}'")

    # 10. agy_federation_mesh
    fm_data = data.get("agy_federation_mesh") or data.get("agy-federation-mesh")
    if fm_data is not None:
        checked_stations.add("agy_federation_mesh")
        if not isinstance(fm_data, dict):
            violations.append("agy_federation_mesh: station payload must be a dict")
        else:
            quorum = fm_data.get("byzantine_quorum_consensus")
            if quorum is not None and isinstance(quorum, dict):
                if quorum.get("consensus_reached") is False:
                    violations.append("agy_federation_mesh: byzantine quorum consensus not reached")
            stealing = fm_data.get("work_stealing_scheduler")
            if stealing is not None and isinstance(stealing, dict):
                if stealing.get("deadlock_free") is False:
                    violations.append("agy_federation_mesh: work_stealing_scheduler reported deadlock")

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

    station_check_v13 = verify_v1_3_station_contracts(payload)
    if station_check_v13["checked_stations"]:
        context["station_v1_3_contracts_verification"] = station_check_v13
        if not station_check_v13["valid"]:
            role = str(payload.get("role") or "").lower().strip()
            if role in ("implementer", "build-agent", "station-agent") or bool(payload.get("enforce_station_contracts")):
                return {
                    "decision": "block",
                    "reason": "v1.3.0 Station contract violation: " + "; ".join(station_check_v13["violations"]),
                }

    station_check_v20 = verify_v2_0_station_contracts(payload)
    if station_check_v20["checked_stations"]:
        context["station_v2_0_contracts_verification"] = station_check_v20
        if not station_check_v20["valid"]:
            role = str(payload.get("role") or "").lower().strip()
            if role in ("implementer", "build-agent", "station-agent") or bool(payload.get("enforce_station_contracts")):
                return {
                    "decision": "block",
                    "reason": "v2.0.0 Station contract violation: " + "; ".join(station_check_v20["violations"]),
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

    station_check_v13 = verify_v1_3_station_contracts(payload)
    if station_check_v13["checked_stations"]:
        context["station_v1_3_contracts_release_verification"] = station_check_v13
        if not station_check_v13["valid"]:
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
                    "reason": "v1.3.0 Station contract violation in release gate: " + "; ".join(station_check_v13["violations"]),
                }

    station_check_v20 = verify_v2_0_station_contracts(payload)
    if station_check_v20["checked_stations"]:
        context["station_v2_0_contracts_release_verification"] = station_check_v20
        if not station_check_v20["valid"]:
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
                    "reason": "v2.0.0 Station contract violation in release gate: " + "; ".join(station_check_v20["violations"]),
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
