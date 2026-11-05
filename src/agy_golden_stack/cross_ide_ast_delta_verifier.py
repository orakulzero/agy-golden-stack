"""Cross-IDE AST Delta Verifier (REQ-GS-DELTAVERIFY-01).

Verifies that automated or dual-agent refactoring preserves all public symbols,
decorators, return type annotations, and `REQ-*` requirement traceability tags
while preventing cyclomatic complexity spikes.

Requirement Traceability:
- REQ-GS-DELTAVERIFY-01: Cross-IDE AST Delta Verifier
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import re
from typing import Any

REQ_TAG_PATTERN = re.compile(r"REQ-[A-Z0-9-]+")


@dataclass(frozen=True)
class ASTDeltaVerificationReport:
    """Structured report of AST equivalence and contract invariants across a refactoring delta (REQ-GS-DELTAVERIFY-01)."""

    passed: bool
    dropped_symbols: list[str] = field(default_factory=list)
    dropped_decorators: list[str] = field(default_factory=list)
    dropped_req_tags: list[str] = field(default_factory=list)
    dropped_return_annotations: list[str] = field(default_factory=list)
    complexity_violations: list[str] = field(default_factory=list)
    complexity_delta: int = 0


class CrossIDEASTDeltaVerifier:
    """Verifies AST structural invariants and selects safer dual-agent refactoring candidates (REQ-GS-DELTAVERIFY-01)."""

    def __init__(self, max_complexity_delta: int = 8) -> None:
        self.max_complexity_delta = int(max_complexity_delta)

    @staticmethod
    def _compute_complexity(node: ast.AST) -> int:
        """Compute McCabe-style cyclomatic complexity of an AST node."""
        branch_types = (
            ast.If,
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.ExceptHandler,
            ast.With,
            ast.AsyncWith,
            ast.BoolOp,
            ast.IfExp,
            ast.comprehension,
        )
        return 1 + sum(1 for child in ast.walk(node) if isinstance(child, branch_types))

    @classmethod
    def _extract_symbol_metadata(cls, source_code: str) -> dict[str, dict[str, Any]]:
        """Extract public symbols, their decorators, return annotations, and complexity."""
        tree = ast.parse(source_code)
        symbols: dict[str, dict[str, Any]] = {}

        for node in tree.body:
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                symbols[node.name] = {
                    "decorators": [ast.unparse(d) for d in node.decorator_list],
                    "has_return": False,
                    "complexity": cls._compute_complexity(node),
                }
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("_"):
                        qual = f"{node.name}.{item.name}"
                        symbols[qual] = {
                            "decorators": [ast.unparse(d) for d in item.decorator_list],
                            "has_return": item.returns is not None,
                            "complexity": cls._compute_complexity(item),
                        }
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                symbols[node.name] = {
                    "decorators": [ast.unparse(d) for d in node.decorator_list],
                    "has_return": node.returns is not None,
                    "complexity": cls._compute_complexity(node),
                }
        return symbols

    @staticmethod
    def _extract_req_tags(source_code: str) -> set[str]:
        """Extract all REQ-* identifiers from module and symbol docstrings/source."""
        return set(REQ_TAG_PATTERN.findall(source_code))

    def verify_ast_delta(
        self,
        baseline_source: str,
        candidate_source: str,
    ) -> ASTDeltaVerificationReport:
        """Verify candidate AST preserves public symbols, decorators, return annotations, and REQ tags (REQ-GS-DELTAVERIFY-01)."""
        base_syms = self._extract_symbol_metadata(baseline_source)
        cand_syms = self._extract_symbol_metadata(candidate_source)

        dropped_symbols: list[str] = []
        dropped_decorators: list[str] = []
        dropped_return_annotations: list[str] = []
        complexity_violations: list[str] = []
        max_delta = 0

        for sym_name, base_meta in base_syms.items():
            if sym_name not in cand_syms:
                dropped_symbols.append(sym_name)
                continue
            cand_meta = cand_syms[sym_name]
            for dec in base_meta["decorators"]:
                if dec not in cand_meta["decorators"]:
                    dropped_decorators.append(f"{sym_name}:@{dec}")
            if base_meta["has_return"] and not cand_meta["has_return"]:
                dropped_return_annotations.append(sym_name)

            delta = cand_meta["complexity"] - base_meta["complexity"]
            if delta > max_delta:
                max_delta = delta
            if delta > self.max_complexity_delta:
                complexity_violations.append(
                    f"{sym_name}: complexity delta +{delta} exceeds max {self.max_complexity_delta}"
                )

        base_reqs = self._extract_req_tags(baseline_source)
        cand_reqs = self._extract_req_tags(candidate_source)
        dropped_req_tags = sorted(base_reqs - cand_reqs)

        passed = not (
            dropped_symbols
            or dropped_decorators
            or dropped_req_tags
            or dropped_return_annotations
            or complexity_violations
        )
        return ASTDeltaVerificationReport(
            passed=passed,
            dropped_symbols=dropped_symbols,
            dropped_decorators=dropped_decorators,
            dropped_req_tags=dropped_req_tags,
            dropped_return_annotations=dropped_return_annotations,
            complexity_violations=complexity_violations,
            complexity_delta=max_delta,
        )

    def select_safer_candidate(
        self,
        baseline_source: str,
        candidate_a: str,
        candidate_b: str,
    ) -> dict[str, Any]:
        """Evaluate two refactoring candidates and return the compliant one with lower complexity delta (REQ-GS-DELTAVERIFY-01)."""
        rep_a = self.verify_ast_delta(baseline_source, candidate_a)
        rep_b = self.verify_ast_delta(baseline_source, candidate_b)

        if rep_b.passed and (not rep_a.passed or rep_b.complexity_delta < rep_a.complexity_delta):
            return {
                "selected": "candidate_b",
                "selected_source": candidate_b,
                "report": rep_b,
                "report_a": rep_a,
                "report_b": rep_b,
            }
        return {
            "selected": "candidate_a",
            "selected_source": candidate_a,
            "report": rep_a,
            "report_a": rep_a,
            "report_b": rep_b,
        }
