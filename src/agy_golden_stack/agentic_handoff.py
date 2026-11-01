"""Cross-IDE Agentic Handoff & Context Serialization Protocol (REQ-GS-HANDOFF-01).

Provides HMAC-SHA256 authenticated handoff envelopes between IDEs, Python AST
symbol focus range extraction, MCP context resource formatting, and P20/P30
GoldenStackBus hygiene invariants.
"""

from __future__ import annotations

import ast
import copy
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any

_REQ_KEY_PATTERN = re.compile(r"^REQ-[A-Z0-9-]+$")


@dataclass
class HandoffEnvelope:
    """Authenticated cross-IDE context handoff envelope (REQ-GS-HANDOFF-01)."""

    source_ide: str
    target_ide: str
    task_id: str
    memory_registers: dict[str, Any]
    req_status: dict[str, str]
    source_files: dict[str, str]
    hmac_signature: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize handoff envelope into a plain dictionary (REQ-GS-HANDOFF-01)."""
        return {
            "source_ide": self.source_ide,
            "target_ide": self.target_ide,
            "task_id": self.task_id,
            "memory_registers": copy.deepcopy(self.memory_registers),
            "req_status": dict(self.req_status),
            "source_files": dict(self.source_files),
            "hmac_signature": self.hmac_signature,
        }


class AgenticHandoffProtocol:
    """Protocol engine for cross-IDE handoff serialization and verification (REQ-GS-HANDOFF-01)."""

    def __init__(self, signing_key: str) -> None:
        """Initialize protocol engine with shared HMAC signing key (REQ-GS-HANDOFF-01)."""
        if not signing_key:
            raise ValueError("signing_key must be non-empty (REQ-GS-HANDOFF-01)")
        self._signing_key = signing_key.encode("utf-8")

    @staticmethod
    def _validate_p20_p30_invariants(
        req_status: dict[str, str],
        source_files: dict[str, str],
    ) -> None:
        """Enforce P20/P30 requirement key syntax and relative path hygiene (REQ-GS-HANDOFF-01)."""
        for req_key in req_status:
            if not _REQ_KEY_PATTERN.match(str(req_key)):
                raise ValueError(
                    f"Invalid requirement tag {req_key!r}; must match REQ-* (REQ-GS-HANDOFF-01)"
                )
        for rel_path in source_files:
            posix_parts = PurePosixPath(rel_path).parts
            win_path = PureWindowsPath(rel_path)
            if (
                not rel_path
                or rel_path.startswith(("/", "\\"))
                or ".." in posix_parts
                or ".." in win_path.parts
                or win_path.drive
            ):
                raise ValueError(
                    f"Unsafe source path {rel_path!r} rejected by P20/P30 guard (REQ-GS-HANDOFF-01)"
                )

    def _compute_signature(
        self,
        source_ide: str,
        target_ide: str,
        task_id: str,
        memory_registers: dict[str, Any],
        req_status: dict[str, str],
        source_files: dict[str, str],
    ) -> str:
        """Compute canonical HMAC-SHA256 over envelope fields (REQ-GS-HANDOFF-01)."""
        canonical_obj = {
            "source_ide": source_ide,
            "target_ide": target_ide,
            "task_id": task_id,
            "memory_registers": memory_registers,
            "req_status": req_status,
            "source_files": source_files,
        }
        canonical_bytes = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._signing_key, canonical_bytes, hashlib.sha256).hexdigest()

    def export_handoff_envelope(
        self,
        source_ide: str,
        target_ide: str,
        task_id: str,
        memory_registers: dict[str, Any],
        req_status: dict[str, str],
        source_files: dict[str, str],
    ) -> HandoffEnvelope:
        """Validate invariants and export signed HandoffEnvelope (REQ-GS-HANDOFF-01)."""
        self._validate_p20_p30_invariants(req_status, source_files)
        sig = self._compute_signature(
            source_ide=source_ide,
            target_ide=target_ide,
            task_id=task_id,
            memory_registers=memory_registers,
            req_status=req_status,
            source_files=source_files,
        )
        return HandoffEnvelope(
            source_ide=source_ide,
            target_ide=target_ide,
            task_id=task_id,
            memory_registers=copy.deepcopy(memory_registers),
            req_status=dict(req_status),
            source_files=dict(source_files),
            hmac_signature=sig,
        )

    def verify_handoff_integrity(self, payload: dict[str, Any] | HandoffEnvelope) -> bool:
        """Verify HMAC-SHA256 integrity of a handoff dictionary or envelope (REQ-GS-HANDOFF-01)."""
        data = payload.to_dict() if isinstance(payload, HandoffEnvelope) else dict(payload)
        sig = data.get("hmac_signature")
        if not isinstance(sig, str) or len(sig) != 64:
            return False
        try:
            expected = self._compute_signature(
                source_ide=str(data["source_ide"]),
                target_ide=str(data["target_ide"]),
                task_id=str(data["task_id"]),
                memory_registers=dict(data["memory_registers"]),
                req_status=dict(data["req_status"]),
                source_files=dict(data["source_files"]),
            )
        except (KeyError, TypeError, ValueError):
            return False
        return hmac.compare_digest(sig, expected)

    def import_handoff_envelope(self, payload: dict[str, Any]) -> HandoffEnvelope:
        """Verify integrity and import dictionary into a HandoffEnvelope (REQ-GS-HANDOFF-01)."""
        if not self.verify_handoff_integrity(payload):
            raise ValueError("Handoff envelope HMAC-SHA256 integrity check failed (REQ-GS-HANDOFF-01)")
        req_status = dict(payload["req_status"])
        source_files = dict(payload["source_files"])
        self._validate_p20_p30_invariants(req_status, source_files)
        return HandoffEnvelope(
            source_ide=str(payload["source_ide"]),
            target_ide=str(payload["target_ide"]),
            task_id=str(payload["task_id"]),
            memory_registers=copy.deepcopy(dict(payload["memory_registers"])),
            req_status=req_status,
            source_files=source_files,
            hmac_signature=str(payload["hmac_signature"]),
        )

    def extract_ast_focus_ranges(self, source: str) -> list[dict[str, Any]]:
        """Extract function and class symbol line boundaries from Python source (REQ-GS-HANDOFF-01)."""
        tree = ast.parse(source)
        ranges: list[dict[str, Any]] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ranges.append(
                    {
                        "symbol": node.name,
                        "kind": "function",
                        "start_line": int(node.lineno),
                        "end_line": int(getattr(node, "end_lineno", node.lineno)),
                    }
                )
            elif isinstance(node, ast.ClassDef):
                ranges.append(
                    {
                        "symbol": node.name,
                        "kind": "class",
                        "start_line": int(node.lineno),
                        "end_line": int(getattr(node, "end_lineno", node.lineno)),
                    }
                )
        return ranges

    def to_mcp_context_resource(self, envelope: HandoffEnvelope) -> dict[str, Any]:
        """Format HandoffEnvelope and AST focus ranges as an MCP resource payload (REQ-GS-HANDOFF-01)."""
        focus_map: dict[str, list[dict[str, Any]]] = {}
        for path, content in envelope.source_files.items():
            if path.endswith(".py"):
                focus_map[path] = self.extract_ast_focus_ranges(content)
        body = {
            "envelope": envelope.to_dict(),
            "ast_focus_ranges": focus_map,
        }
        return {
            "uri": f"mcp://golden-stack/handoff/{envelope.task_id}",
            "mimeType": "application/json",
            "text": json.dumps(body, sort_keys=True),
        }
