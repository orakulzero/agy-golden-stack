"""
Edge cases, boundary inputs, and invariant checks for GoldenStackBus.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from agy_golden_stack.bus import GoldenStackBus


def test_edge_case_pre_tool_use_bare_cu_prefix(tmp_path: Path) -> None:
    """
    Test that dispatches an event named "PreToolUse" with payload={"tool_name": "cu_"}
    and asserts the CUA safety interceptor path is triggered.
    It verifies the boundary condition of the startswith("cu_") matcher never silently 
    falls through to normal P10..P50 slot execution without inspection.
    """
    bus = GoldenStackBus(workspace_root=tmp_path, config_root=tmp_path)
    
    event_name = "PreToolUse"
    payload = {"tool_name": "cu_"}
    
    result = bus.dispatch(event_name, payload)
    
    # Assert CUA safety interceptor path is triggered
    assert "context" in result, "Result must contain context"
    assert "cua_safety_inspection" in result["context"], (
        "CUA safety interceptor path was not triggered for bare 'cu_' prefix"
    )
    
    cua_res = result["context"]["cua_safety_inspection"]
    
    # Assert it returns either an explicit allowed decision or a block decision 
    # with blocked_by == "CUA_SAFETY_INTERCEPTOR"
    if result.get("decision") == "block":
        assert result.get("blocked_by") == "CUA_SAFETY_INTERCEPTOR"
        assert cua_res.get("allowed", True) is False
    else:
        # If it fell through to allow, cua_res must have allowed=True
        assert cua_res.get("allowed", True) is True
