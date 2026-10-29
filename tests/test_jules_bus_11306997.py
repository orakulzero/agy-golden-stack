import sys
from pathlib import Path

# Add src to sys.path if not present
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import pytest
from unittest.mock import patch
from agy_golden_stack.bus import GoldenStackBus

def test_reentrant_short_circuit_active_depth():
    """
    Test that an event beginning with 'ComputerUse' dispatched when
    _active_depth > 0 bypasses the safety interceptor and short-circuits.
    """
    bus = GoldenStackBus(register_defaults=False)
    bus._active_depth = 1  # Simulate nested dispatch

    with patch('agy_golden_stack.bus.inspect_computer_use_bus_event') as mock_inspect:
        # Setup mock to block the event (allowed=False), if it gets called
        mock_inspect.return_value = {"allowed": False, "reason": "Blocked for testing"}
        
        result = bus.dispatch("ComputerUse_TestEvent", {})
        
        # Assert re-entrancy short-circuit wins
        assert result["decision"] == "allow"
        assert result["reentrant_short_circuit"] is True
        assert result["blocked_by"] is None
        assert result["executed_slots"] == []
        assert result["total_duration_ms"] == 0.0
        
        # The safety interceptor must NOT be invoked
        mock_inspect.assert_not_called()

def test_reentrant_short_circuit_payload_flag():
    """
    Test that an event beginning with 'ComputerUse' dispatched when
    payload contains _golden_bus_active=True bypasses the safety interceptor
    and short-circuits.
    """
    bus = GoldenStackBus(register_defaults=False)
    
    with patch('agy_golden_stack.bus.inspect_computer_use_bus_event') as mock_inspect:
        # Setup mock to block the event (allowed=False), if it gets called
        mock_inspect.return_value = {"allowed": False, "reason": "Blocked for testing"}
        
        result = bus.dispatch("ComputerUse_TestEvent", {"_golden_bus_active": True})
        
        # Assert re-entrancy short-circuit wins
        assert result["decision"] == "allow"
        assert result["reentrant_short_circuit"] is True
        assert result["blocked_by"] is None
        assert result["executed_slots"] == []
        assert result["total_duration_ms"] == 0.0
        
        # The safety interceptor must NOT be invoked
        mock_inspect.assert_not_called()
