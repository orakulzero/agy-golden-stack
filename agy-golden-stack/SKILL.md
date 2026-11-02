# Cursor & Windsurf AST-First Refactoring Guard Skill

**Required Tags**: REQ-001, REQ-002, REQ-003, REQ-004, REQ-005, REQ-BUS-PROMPT-01, REQ-GS-201, REQ-GS-202, REQ-GS-HANDOFF-01, REQ-GS-M3, REQ-GS-PATCH-01, REQ-GS-TDD-01

## 1. Core Mandate
This skill guards the refactoring process across cross-IDE agentic loops, specifically between **Cursor** and **Windsurf**. It strictly mandates AST-aware, surgical patches to prevent destructive full-file replacements and enforces cryptographic handoff envelopes for session continuity.

## 2. AST-First Refactoring Rules (REQ-GS-PATCH-01)
When modifying source code during a refactor task:
1.  **Surgical Slices Only**: Never replace an entire file. Use `ASTPatchValidator.find_boundary(source_code, symbol_name)` or `find_ast_symbol_boundary` to accurately determine the `start_line` and `end_line` of the target node.
2.  **Apply Targeted Edits**: Execute the modification strictly via `apply_range_edit_slice(original_code, start_line, end_line, replacement_content)`.
3.  **AST Boundary Enforcement**: Always validate edits with `ASTPatchValidator.validate_patch(original, modified, symbol)` to ensure syntactic integrity.
4.  **Import Merging**: Ensure new dependencies are merged without clobbering existing module imports via `validate_additive_imports()`.

## 3. Cross-IDE Agentic Handoff Protocol (REQ-GS-HANDOFF-01)
When transferring task context between Cursor and Windsurf (or any independent agent instances):
1.  **Export Envelopes**: Always serialize the current state using `AgenticHandoffProtocol.export_handoff_envelope(source_ide, target_ide, task_id, memory_registers, req_status, source_files)`.
2.  **Verify Integrity**: The receiving IDE instance must invoke `AgenticHandoffProtocol.verify_handoff_integrity(payload)` and `import_handoff_envelope()` upon waking to validate the payload's cryptographic signature (`_compute_signature`).
3.  **Focus Ranges**: Extract active working areas in the target IDE using `extract_ast_focus_ranges(source)` to immediately regain spatial context.
4.  **Format Mapping**: Transform the envelope into the local environment context using `to_mcp_context_resource(envelope)`.

## 4. TDD & UB Guard Integrations (REQ-GS-TDD-01)
Refactoring operations must abide by the Golden Stack's existing gates:
*   Ensure that AST slices respect `TDDGate` sequence invariants (test generation prior to logic modification) via `evaluate_tdd_precommit_gate()`.
*   Check for unintentionally duplicated logic during extractions using `UBModeGuard.check_duplicate_abstractions(source_code)`.
*   Ensure that `P20` (`brain_memory`) and `P30` (`iso9000_gate`) bus slots correctly register the new definitions and validate standard contracts.
