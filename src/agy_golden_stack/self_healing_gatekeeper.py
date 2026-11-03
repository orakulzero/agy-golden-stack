"""Autonomous Self-Healing Pipeline Gatekeeper (REQ-GS-GATEKEEPER-01).

Provides diagnostic-to-AST symbol span localization, deterministic surgical
RangeEdit heal prompt generation, and unbalanced syntax symbol fallback
restoration across station repositories.
"""

from __future__ import annotations

import ast
import re
from typing import Any

_SYNTAX_DIAG_RE = re.compile(
    r"SyntaxError in ([^\s:]+):.*?line (\d+)",
    re.IGNORECASE,
)
_MISSING_SYM_RE = re.compile(
    r"missing top-level (?:func|class|symbol) '([^']+)' in ([^\s:]+)",
    re.IGNORECASE,
)
_SIG_REGR_RE = re.compile(
    r"signature regression on '([^']+)' in ([^\s:]+)",
    re.IGNORECASE,
)
_TOP_DEF_HEADER_RE = re.compile(
    r"^(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)


def _extract_ast_symbol_spans(source_code: str) -> list[dict[str, Any]]:
    """REQ-GS-GATEKEEPER-01: Extract top-level AST symbol spans (1-indexed inclusive)."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    lines = source_code.splitlines()
    spans: list[dict[str, Any]] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start_line = int(getattr(node, "lineno", 1))
        for dec in getattr(node, "decorator_list", None) or []:
            d_line = getattr(dec, "lineno", None)
            if d_line is not None:
                start_line = min(start_line, int(d_line))
        end_line = int(getattr(node, "end_lineno", start_line))
        snippet = "\n".join(lines[start_line - 1 : end_line]) + "\n"
        spans.append(
            {
                "symbol_name": node.name,
                "start_line": start_line,
                "end_line": end_line,
                "source": snippet,
            }
        )
    return spans


class SelfHealingGatekeeper:
    """REQ-GS-GATEKEEPER-01: Autonomous Self-Healing Pipeline Gatekeeper."""

    def parse_gate_diagnostics(
        self,
        diagnostics: list[str],
        source_files: dict[str, str],
    ) -> list[dict[str, Any]]:
        """REQ-GS-GATEKEEPER-01: Map gate diagnostics to exact file and AST symbol spans."""
        failures: list[dict[str, Any]] = []
        for diag in diagnostics:
            file_path = ""
            symbol_name = ""
            defect_kind = ""
            err_line: int | None = None

            m_syn = _SYNTAX_DIAG_RE.search(diag)
            if m_syn:
                file_path = m_syn.group(1).strip()
                err_line = int(m_syn.group(2))
                defect_kind = "syntax_error"
            else:
                m_miss = _MISSING_SYM_RE.search(diag)
                if m_miss:
                    symbol_name = m_miss.group(1).strip()
                    file_path = m_miss.group(2).strip()
                    defect_kind = "missing_symbol"
                else:
                    m_sig = _SIG_REGR_RE.search(diag)
                    if m_sig:
                        symbol_name = m_sig.group(1).strip()
                        file_path = m_sig.group(2).strip()
                        defect_kind = "signature_regression"

            if not file_path:
                for cand_path in source_files:
                    if cand_path in diag:
                        file_path = cand_path
                        defect_kind = defect_kind or "gate_failure"
                        break

            if not file_path or file_path not in source_files:
                continue

            src = source_files[file_path]
            spans = _extract_ast_symbol_spans(src)
            matched_span: dict[str, Any] | None = None

            if symbol_name:
                for sp in spans:
                    if sp["symbol_name"] == symbol_name:
                        matched_span = sp
                        break

            if matched_span is None and err_line is not None:
                for sp in spans:
                    if sp["start_line"] <= err_line <= sp["end_line"]:
                        matched_span = sp
                        break

            if matched_span is None and spans:
                matched_span = spans[0]

            if matched_span is not None:
                failures.append(
                    {
                        "file_path": file_path,
                        "symbol_name": str(matched_span["symbol_name"]),
                        "start_line": int(matched_span["start_line"]),
                        "end_line": int(matched_span["end_line"]),
                        "defect_kind": defect_kind or "ast_gate_failure",
                        "diagnostic": diag,
                    }
                )
        return failures

    def build_surgical_heal_prompt(
        self,
        failures: list[dict[str, Any]],
        source_files: dict[str, str],
    ) -> str:
        """REQ-GS-GATEKEEPER-01: Build deterministic surgical RangeEdit heal prompt with numbered AST slices."""
        sections: list[str] = [
            "# Surgical Self-Healing Gatekeeper Instructions (REQ-GS-GATEKEEPER-01)",
            "Emit targeted RangeEdit blocks for each localized AST symbol failure below:",
        ]
        seen: set[tuple[str, int, int]] = set()
        for item in failures:
            fpath = str(item.get("file_path", ""))
            s_line = int(item.get("start_line", 1))
            e_line = int(item.get("end_line", s_line))
            sym = str(item.get("symbol_name", ""))
            kind = str(item.get("defect_kind", "defect"))
            key = (fpath, s_line, e_line)
            if key in seen:
                continue
            seen.add(key)

            src = source_files.get(fpath, "")
            lines = src.splitlines()
            numbered_slice = "\n".join(
                f"{idx}: {lines[idx - 1]}"
                for idx in range(max(1, s_line), min(len(lines), e_line) + 1)
            )
            sections.append(
                f"## Failure in `{fpath}` symbol `{sym}` ({kind})\n"
                f"### RangeEdit: {fpath}:{s_line}-{e_line}\n"
                f"```python\n{numbered_slice}\n```"
            )
        return "\n\n".join(sections)

    def auto_repair_unbalanced_syntax(
        self,
        candidate_code: str,
        original_code: str,
    ) -> dict[str, Any]:
        """REQ-GS-GATEKEEPER-01: Restore truncated or unbalanced AST symbols from baseline while keeping healthy edits."""
        try:
            ast.parse(candidate_code)
            return {
                "repaired": True,
                "restored_symbols": [],
                "code": candidate_code,
            }
        except SyntaxError:
            pass

        baseline_spans = {
            sp["symbol_name"]: sp["source"]
            for sp in _extract_ast_symbol_spans(original_code)
        }
        cand_lines = candidate_code.splitlines()
        valid_prefix_lines: list[str] = []
        broken_symbol: str | None = None

        for idx in range(len(cand_lines), 0, -1):
            prefix_candidate = "\n".join(cand_lines[:idx]) + "\n"
            try:
                ast.parse(prefix_candidate)
                valid_prefix_lines = cand_lines[:idx]
                for rem_line in cand_lines[idx:]:
                    m_hdr = _TOP_DEF_HEADER_RE.match(rem_line.strip())
                    if m_hdr:
                        broken_symbol = m_hdr.group(1)
                        break
                break
            except SyntaxError:
                continue

        if not valid_prefix_lines:
            return {
                "repaired": True,
                "restored_symbols": list(baseline_spans.keys()),
                "code": original_code,
            }

        prefix_code = "\n".join(valid_prefix_lines).rstrip() + "\n"
        present_syms = {
            sp["symbol_name"] for sp in _extract_ast_symbol_spans(prefix_code)
        }
        restored_symbols: list[str] = []
        repaired_chunks: list[str] = [prefix_code]

        for sym_name, sym_src in baseline_spans.items():
            if sym_name not in present_syms or sym_name == broken_symbol:
                restored_symbols.append(sym_name)
                repaired_chunks.append(sym_src.rstrip() + "\n")

        repaired_code = "\n".join(chunk.rstrip() for chunk in repaired_chunks) + "\n"
        try:
            ast.parse(repaired_code)
            return {
                "repaired": True,
                "restored_symbols": restored_symbols,
                "code": repaired_code,
            }
        except SyntaxError:
            return {
                "repaired": True,
                "restored_symbols": list(baseline_spans.keys()),
                "code": original_code,
            }
