"""Locked Agile V verification suite for Cross-IDE Agentic Handoff Protocol.

Requirement Traceability:
- REQ-GS-HANDOFF-01: Cross-IDE Agentic Handoff & Context Serialization Protocol
  (MCP Context Exchange) with HMAC-SHA256 integrity, AST focus range extraction,
  and GoldenStackBus P20/P30 validation invariants.

Hygiene: 100% English-only (0 Cyrillic characters).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agy_golden_stack.agentic_handoff import (  # noqa: E402
    AgenticHandoffProtocol,
    HandoffEnvelope,
)


def test_export_and_import_handoff_envelope_roundtrip() -> None:
    """Verify export, HMAC-SHA256 signing, and lossless import roundtrip of HandoffEnvelope (REQ-GS-HANDOFF-01)."""
    proto = AgenticHandoffProtocol(signing_key="gs-handoff-key")
    env = proto.export_handoff_envelope(
        source_ide="windsurf",
        target_ide="claude-code",
        task_id="T-42",
        memory_registers={"active_branch": "main"},
        req_status={"REQ-GS-HANDOFF-01": "VERIFIED"},
        source_files={"src/mod.py": "def alpha():\n    return 1\n"},
    )
    assert isinstance(env, HandoffEnvelope)
    assert isinstance(env.hmac_signature, str) and len(env.hmac_signature) == 64

    payload_dict = env.to_dict()
    assert proto.verify_handoff_integrity(payload_dict) is True

    restored = proto.import_handoff_envelope(payload_dict)
    assert isinstance(restored, HandoffEnvelope)
    assert restored.source_ide == "windsurf"
    assert restored.target_ide == "claude-code"
    assert restored.task_id == "T-42"
    assert restored.memory_registers == {"active_branch": "main"}
    assert restored.req_status == {"REQ-GS-HANDOFF-01": "VERIFIED"}
    assert restored.source_files == {"src/mod.py": "def alpha():\n    return 1\n"}
    assert restored.hmac_signature == env.hmac_signature


def test_tampered_handoff_envelope_rejected() -> None:
    """Verify tampering with memory_registers or hmac_signature fails integrity and raises ValueError (REQ-GS-HANDOFF-01)."""
    proto = AgenticHandoffProtocol(signing_key="gs-handoff-key")
    env = proto.export_handoff_envelope(
        source_ide="windsurf",
        target_ide="claude-code",
        task_id="T-42",
        memory_registers={"active_branch": "main"},
        req_status={"REQ-GS-HANDOFF-01": "VERIFIED"},
        source_files={"src/mod.py": "def alpha():\n    return 1\n"},
    )

    tampered_reg = copy.deepcopy(env.to_dict())
    tampered_reg["memory_registers"]["active_branch"] = "compromised"
    assert proto.verify_handoff_integrity(tampered_reg) is False
    with pytest.raises(ValueError):
        proto.import_handoff_envelope(tampered_reg)

    tampered_sig = copy.deepcopy(env.to_dict())
    tampered_sig["hmac_signature"] = "0" * 64
    assert proto.verify_handoff_integrity(tampered_sig) is False
    with pytest.raises(ValueError):
        proto.import_handoff_envelope(tampered_sig)


def test_extract_ast_focus_ranges_from_python_source() -> None:
    """Verify AST focus range extraction returns function and class symbol line boundaries (REQ-GS-HANDOFF-01)."""
    proto = AgenticHandoffProtocol(signing_key="gs-handoff-key")
    source = "def alpha():\n    return 1\n\nclass Beta:\n    pass\n"
    ranges = proto.extract_ast_focus_ranges(source)

    assert isinstance(ranges, list)
    assert len(ranges) == 2
    by_sym = {item["symbol"]: item for item in ranges}
    assert "alpha" in by_sym
    assert by_sym["alpha"]["kind"] == "function"
    assert by_sym["alpha"]["start_line"] == 1
    assert by_sym["alpha"]["end_line"] == 2

    assert "Beta" in by_sym
    assert by_sym["Beta"]["kind"] == "class"
    assert by_sym["Beta"]["start_line"] == 4
    assert by_sym["Beta"]["end_line"] == 5


def test_mcp_context_payload_formatting() -> None:
    """Verify MCP resource formatting produces uri, application/json mimeType, and AST focus ranges (REQ-GS-HANDOFF-01)."""
    proto = AgenticHandoffProtocol(signing_key="gs-handoff-key")
    env = proto.export_handoff_envelope(
        source_ide="windsurf",
        target_ide="claude-code",
        task_id="T-99",
        memory_registers={"step": 3},
        req_status={"REQ-GS-HANDOFF-01": "VERIFIED"},
        source_files={"src/mod.py": "def alpha():\n    return 1\n"},
    )
    mcp_payload = proto.to_mcp_context_resource(env)
    assert isinstance(mcp_payload, dict)
    assert "uri" in mcp_payload and "T-99" in str(mcp_payload["uri"])
    assert mcp_payload.get("mimeType") == "application/json"

    parsed_text = json.loads(mcp_payload["text"])
    assert isinstance(parsed_text, dict)
    assert "ast_focus_ranges" in parsed_text or "focus_ranges" in parsed_text or "envelope" in parsed_text


def test_golden_stack_bus_p20_p30_handoff_integration() -> None:
    """Verify P20/P30 guard rejects non-REQ keys in req_status and path traversal in source_files (REQ-GS-HANDOFF-01)."""
    proto = AgenticHandoffProtocol(signing_key="gs-handoff-key")

    with pytest.raises(ValueError):
        proto.export_handoff_envelope(
            source_ide="windsurf",
            target_ide="claude-code",
            task_id="T-bad-req",
            memory_registers={},
            req_status={"BAD-KEY-01": "VERIFIED"},
            source_files={"src/mod.py": "x = 1\n"},
        )

    with pytest.raises(ValueError):
        proto.export_handoff_envelope(
            source_ide="windsurf",
            target_ide="claude-code",
            task_id="T-bad-path",
            memory_registers={},
            req_status={"REQ-GS-HANDOFF-01": "VERIFIED"},
            source_files={"../secret.py": "x = 1\n"},
        )


def test_req_gs_handoff_01_traceability_and_english_hygiene() -> None:
    """Verify REQ-GS-HANDOFF-01 tag and 0 Cyrillic characters in implementation and tests (REQ-GS-HANDOFF-01)."""
    impl_path = SRC_DIR / "agy_golden_stack" / "agentic_handoff.py"
    assert impl_path.is_file(), f"Implementation file missing: {impl_path}"
    impl_text = impl_path.read_text(encoding="utf-8")
    test_text = Path(__file__).read_text(encoding="utf-8")

    assert "REQ-GS-HANDOFF-01" in impl_text
    assert re.search(r"[\u0400-\u04FF]", impl_text) is None
    assert re.search(r"[\u0400-\u04FF]", test_text) is None
