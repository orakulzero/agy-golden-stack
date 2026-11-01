"""AST-First Surgical Patch and Refactor Validator.

Traceability:
- REQ-GS-PATCH-01: AST symbol boundary extraction and RangeEdit patch validation on files >180 lines.

Quality Framework: ISO 9001:2015, ISO/IEC 42001:2023, Agile V.
Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Set, Tuple


def find_ast_symbol_boundary(source_code: str, symbol_name: str) -> Tuple[int, int, str]:
    """Extract 1-indexed (start_line, end_line, symbol_type) of named function or class (REQ-GS-PATCH-01)."""
    tree = ast.parse(source_code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol_name:
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)
                return start_line, end_line, type(node).__name__
    raise ValueError(f"Symbol '{symbol_name}' not found in AST (REQ-GS-PATCH-01)")


def apply_range_edit_slice(
    original_code: str,
    start_line: int,
    end_line: int,
    replacement_content: str,
) -> str:
    """Replace [start_line..end_line] inclusive (1-indexed) preserving bytes outside slice (REQ-GS-PATCH-01)."""
    lines = original_code.splitlines(keepends=True)
    prefix = "".join(lines[: start_line - 1])
    suffix = "".join(lines[end_line:])
    return prefix + replacement_content + suffix


def _extract_imported_symbols(tree: ast.AST) -> Set[str]:
    imported: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                imported.add(f"{mod}.{alias.name}" if mod else alias.name)
                imported.add(alias.name)
                if mod:
                    imported.add(mod)
    return imported


def validate_additive_imports(original_code: str, modified_code: str) -> Dict[str, Any]:
    """Ensure modified code does not delete or truncate existing import statements (REQ-GS-PATCH-01)."""
    try:
        orig_tree = ast.parse(original_code)
        mod_tree = ast.parse(modified_code)
    except SyntaxError as exc:
        return {"is_valid": False, "error": f"Syntax error during import validation: {exc}", "missing_imports": []}

    orig_imports = _extract_imported_symbols(orig_tree)
    mod_imports = _extract_imported_symbols(mod_tree)

    missing = sorted(list(orig_imports - mod_imports))
    if missing:
        return {
            "is_valid": False,
            "error": f"Refactoring deleted existing imports: {missing}",
            "missing_imports": missing,
        }
    return {
        "is_valid": True,
        "error": None,
        "missing_imports": [],
    }


def validate_ast_surgical_patch(
    original_code: str,
    modified_code: str,
    target_symbol: str | None = None,
) -> Dict[str, Any]:
    """Validate syntax and additive imports across original and modified AST (REQ-GS-PATCH-01)."""
    try:
        ast.parse(modified_code)
    except SyntaxError as exc:
        return {"is_valid": False, "reason": f"Patched code fails AST parsing: {exc}"}

    import_check = validate_additive_imports(original_code, modified_code)
    if not import_check["is_valid"]:
        return {"is_valid": False, "reason": import_check["error"], "missing_imports": import_check["missing_imports"]}

    if target_symbol:
        try:
            find_ast_symbol_boundary(modified_code, target_symbol)
        except ValueError as exc:
            return {"is_valid": False, "reason": str(exc)}

    return {"is_valid": True, "reason": "AST surgical patch validated"}


def check_ast_boundaries_before_refactor(source_code: str, symbol_name: str) -> Dict[str, Any]:
    """Pre-refactor verification ensuring target symbol has identifiable AST boundary (REQ-GS-PATCH-01)."""
    try:
        s, e, st = find_ast_symbol_boundary(source_code, symbol_name)
        return {"valid": True, "start_line": s, "end_line": e, "symbol_type": st}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


validate_surgical_range_edit = validate_ast_surgical_patch
check_additive_imports = validate_additive_imports


class ASTPatchValidator:
    """Surgical patch and boundary validator enforcing AST integrity on files >180 lines (REQ-GS-PATCH-01)."""

    @staticmethod
    def find_boundary(source_code: str, symbol_name: str) -> Tuple[int, int, str]:
        return find_ast_symbol_boundary(source_code, symbol_name)

    @staticmethod
    def apply_slice(original_code: str, start: int, end: int, replacement: str) -> str:
        return apply_range_edit_slice(original_code, start, end, replacement)

    @staticmethod
    def validate_patch(original: str, modified: str, symbol: str | None = None) -> Dict[str, Any]:
        return validate_ast_surgical_patch(original, modified, target_symbol=symbol)

    @staticmethod
    def validate_imports(original: str, modified: str) -> Dict[str, Any]:
        return validate_additive_imports(original, modified)
