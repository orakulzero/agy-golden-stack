"""Pre-Commit Agile V TDD Role Separation Gate.

Traceability:
- REQ-GS-TDD-01: Agile V pre-commit gate enforcing test locking and role separation.

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from agy_golden_stack.slots import verify_locked_test_hashes


def validate_role_path_permissions(
    role: str,
    target_path: str,
    tool_name: str = "write_file",
) -> Dict[str, Any]:
    """Validate Agile V role-path separation boundaries (REQ-GS-TDD-01)."""
    norm_role = str(role or "").lower().strip()
    norm_path = str(target_path or "").replace("\\", "/").lstrip("./")
    parts = [p.lower() for p in norm_path.split("/") if p]

    in_tests = "tests" in parts or norm_path.lower().startswith("tests/")
    in_src = (
        "src" in parts
        or "backend" in parts
        or "frontend" in parts
        or norm_path.lower().startswith(("src/", "backend/", "frontend/"))
    )

    if norm_role in ("implementer", "build-agent") and in_tests:
        return {
            "allowed": False,
            "decision": "block",
            "reason": (
                f"Self-Grading Bias violation: role '{role}' cannot modify locked test file '{target_path}'"
            ),
        }

    if norm_role == "test-designer" and in_src:
        return {
            "allowed": False,
            "decision": "block",
            "reason": (
                f"Self-Grading Bias violation: role '{role}' cannot modify implementation file '{target_path}'"
            ),
        }

    return {
        "allowed": True,
        "decision": "allow",
        "reason": f"Role '{role}' authorized for path '{target_path}'",
    }


def evaluate_tdd_precommit_gate(
    workspace_root: Path | str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Pre-commit evaluation requiring locked test hashes for staged implementation files (REQ-GS-TDD-01)."""
    root = Path(workspace_root).resolve()
    staged_files: List[str] = payload.get("staged_files", [])
    locked_hashes: Dict[str, str] = payload.get("locked_test_hashes", {})

    staged_impl_files: List[str] = []
    for f in staged_files:
        norm = str(f).replace("\\", "/").lstrip("./")
        parts = [p.lower() for p in norm.split("/") if p]
        if "src" in parts or norm.startswith("src/"):
            staged_impl_files.append(f)

    if staged_impl_files:
        if not locked_hashes:
            return {
                "decision": "block",
                "reason": (
                    f"Missing locked verification tests for staged implementation files: {staged_impl_files} (REQ-GS-TDD-01)"
                ),
                "staged_implementation_files": staged_impl_files,
            }

        verification = verify_locked_test_hashes(root, locked_hashes)
        if not verification.get("valid"):
            return {
                "decision": "block",
                "reason": (
                    f"Locked test SHA-256 verification failed on staged changes: {verification.get('mismatches')} (REQ-GS-TDD-01)"
                ),
                "mismatches": verification.get("mismatches"),
            }

    return {
        "decision": "allow",
        "reason": "Agile V TDD pre-commit gate passed with verified locked test suite",
        "staged_files_count": len(staged_files),
    }


class TDDGate:
    """Pre-commit gatekeeper enforcing Agile V test locking and role boundaries (REQ-GS-TDD-01)."""

    def __init__(self, workspace_root: Path | str) -> None:
        self.workspace_root = Path(workspace_root).resolve()

    def validate_permissions(self, role: str, target_path: str, tool_name: str = "write_file") -> Dict[str, Any]:
        return validate_role_path_permissions(role, target_path, tool_name=tool_name)

    def verify_hashes(self, locked_hashes: Dict[str, str]) -> Dict[str, Any]:
        return verify_locked_test_hashes(self.workspace_root, locked_hashes)

    def evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return evaluate_tdd_precommit_gate(self.workspace_root, payload)
