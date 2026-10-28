"""Uncle Bob Martin's ub-mode and Maevyn's Anti-Decoherence Guard.

Enforces TDD Rule 1 (test-first invariant) and detects duplicate abstractions.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple


@dataclass(frozen=True)
class UBModeCheckResult:
    """Immutable result of a UB-mode compliance evaluation."""

    is_compliant: bool
    rule_name: str
    violations: List[str] = field(default_factory=list)


def _is_production_file(filepath: str) -> bool:
    norm = filepath.replace("\\", "/").lstrip("./")
    parts = [p.lower() for p in norm.split("/") if p]
    if "tests" in parts or norm.lower().startswith("tests/"):
        return False
    return "src" in parts or norm.lower().startswith("src/")


class UBModeGuard:
    """Guard implementing Uncle Bob's TDD Rule 1 and Anti-Decoherence rules."""

    def verify_tdd_sequence(
        self,
        modified_files: List[str],
        test_files: List[str],
    ) -> UBModeCheckResult:
        """Verify Uncle Bob's TDD Rule 1: production files require tests.

        Production code under src/ must not be modified unless accompanied
        by corresponding test files under tests/.
        """
        prod_files = [f for f in modified_files if _is_production_file(f)]
        has_tests = any(tf and tf.strip() for tf in test_files)

        if prod_files and not has_tests:
            return UBModeCheckResult(
                is_compliant=False,
                rule_name="TDD_TEST_FIRST",
                violations=[
                    f"TDD Rule 1 violation: Production files {prod_files} modified without accompanying test files in tests/."
                ],
            )
        return UBModeCheckResult(
            is_compliant=True,
            rule_name="TDD_TEST_FIRST",
            violations=[],
        )

    def check_duplicate_abstractions(self, source_code: str) -> UBModeCheckResult:
        """Parse source_code and detect redundant parallel classes or duplicate logic."""
        try:
            tree = ast.parse(source_code)
        except (SyntaxError, ValueError) as exc:
            return UBModeCheckResult(
                is_compliant=False,
                rule_name="NO_DUPLICATION",
                violations=[f"Syntax error parsing source code: {exc}"],
            )

        violations: List[str] = []
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]

        for i in range(len(classes)):
            for j in range(i + 1, len(classes)):
                cls_a = classes[i]
                cls_b = classes[j]

                methods_a = [
                    m for m in cls_a.body
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                methods_b = [
                    m for m in cls_b.body
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]

                non_dunder_a = [m for m in methods_a if not m.name.startswith("__")]
                non_dunder_b = [m for m in methods_b if not m.name.startswith("__")]

                names_a = sorted(m.name for m in non_dunder_a)
                names_b = sorted(m.name for m in non_dunder_b)

                if names_a and names_a == names_b:
                    sigs_a = sorted((m.name, tuple(a.arg for a in m.args.args)) for m in non_dunder_a)
                    sigs_b = sorted((m.name, tuple(a.arg for a in m.args.args)) for m in non_dunder_b)
                    if sigs_a == sigs_b:
                        violations.append(
                            f"Duplicate parallel classes detected: '{cls_a.name}' and '{cls_b.name}' share identical method signatures {names_a}."
                        )
                        continue

                bodies_a = sorted(ast.dump(ast.Module(body=m.body, type_ignores=[])) for m in methods_a)
                bodies_b = sorted(ast.dump(ast.Module(body=m.body, type_ignores=[])) for m in methods_b)
                if bodies_a and bodies_a == bodies_b:
                    violations.append(
                        f"Duplicate parallel abstraction detected: '{cls_a.name}' and '{cls_b.name}' share identical class logic."
                    )

        top_funcs = [
            n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for i in range(len(top_funcs)):
            for j in range(i + 1, len(top_funcs)):
                fn_a = top_funcs[i]
                fn_b = top_funcs[j]
                body_a = ast.dump(ast.Module(body=fn_a.body, type_ignores=[]))
                body_b = ast.dump(ast.Module(body=fn_b.body, type_ignores=[]))
                args_a = tuple(a.arg for a in fn_a.args.args)
                args_b = tuple(a.arg for a in fn_b.args.args)
                if args_a == args_b and body_a == body_b:
                    violations.append(
                        f"Duplicate helper abstraction detected: functions '{fn_a.name}' and '{fn_b.name}' share identical implementation logic."
                    )

        if violations:
            return UBModeCheckResult(
                is_compliant=False,
                rule_name="NO_DUPLICATION",
                violations=violations,
            )
        return UBModeCheckResult(
            is_compliant=True,
            rule_name="NO_DUPLICATION",
            violations=[],
        )

    def evaluate_bus_hook(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate hook execution in < 1.0ms, returning allow or block decision."""
        payload = context.get("payload") if isinstance(context.get("payload"), dict) else context
        if not isinstance(payload, dict):
            payload = {}

        modified_files = list(payload.get("modified_files") or [])
        if not modified_files:
            raw_target = payload.get("target_path") or payload.get("path")
            if raw_target:
                modified_files = [str(raw_target)]

        test_files = list(payload.get("test_files") or [])

        tdd_res = self.verify_tdd_sequence(modified_files, test_files)
        if not tdd_res.is_compliant:
            return {
                "decision": "block",
                "reason": f"TDD Violation: {'; '.join(tdd_res.violations)}",
                "check_result": tdd_res,
            }

        source_code = payload.get("source_code") or payload.get("content")
        if source_code and isinstance(source_code, str):
            dup_res = self.check_duplicate_abstractions(source_code)
            if not dup_res.is_compliant:
                return {
                    "decision": "block",
                    "reason": f"Anti-Decoherence Violation: {'; '.join(dup_res.violations)}",
                    "check_result": dup_res,
                }

        return {
            "decision": "allow",
            "check_result": tdd_res,
        }
