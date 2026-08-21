"""
Tests for Guacamole activity detection logic.
Only mouse and keyboard events constitute user activity.
"""
import pytest

from lib.cuckoo.common.guac_utils import is_user_activity


class TestGuacamoleActivityDetection:
    """Test Guacamole activity detection logic."""

    @pytest.mark.parametrize(
        "message,expected,description",
        [
            # Active user interactions (should return True)
            ("5.mouse,3.100,3.200,1.0;", True, "Mouse move"),
            ("5.mouse,3.100,3.200,1.1;", True, "Mouse click"),
            ("3.key,2.65,1.1;", True, "Keyboard input"),
            # Passive or non-user-driven events (should return False)
            ("4.size,4.1280,4.1024;", False, "Window resize"),
            ("4.sync,3.123;", False, "Sync message"),
            ("3.nop;", False, "No-op"),
            ("3.ack,3.456,1.0,7.SUCCESS;", False, "Acknowledgment"),
            ("4.blob,4.data;", False, "Blob data"),
            ("5.touch,1.1,3.100,3.200,2.10,2.10,1.0,3.0.5;", False, "Touch input"),
            ("9.clipboard,5.hello;", False, "Clipboard paste"),
            # Edge cases
            ("", False, "Empty message"),
            ("invalid", False, "Invalid format"),
            ("mouse.100,200,1;", False, "Legacy fake format"),
            ("6.random,4.text;", False, "Unknown instruction"),
        ],
    )
    def test_activity_detection(self, message, expected, description):
        """Test activity detection against real Guacamole protocol messages."""
        result = is_user_activity(message)
        assert result == expected, f"Failed for {description}: '{message}' -> {result} (expected {expected})"

    def test_multiple_instructions_mixed(self):
        """Test activity detection with multiple instructions in one message."""
        # Mixed active and passive instructions - should detect activity
        message = "4.sync,3.123;5.mouse,3.100,3.200,1.1;3.nop;"
        result = is_user_activity(message)
        assert result is True, "Should detect activity when mixed with passive events"
        # Only passive instructions - should not detect activity
        message = "4.sync,3.123;4.size,4.1280,4.1024;3.nop;"
        result = is_user_activity(message)
        assert result is False, "Should not detect activity with only passive events"

    def test_malformed_messages_handled_gracefully(self):
        """Test that malformed messages don't cause crashes."""
        malformed_messages = [
            "5.mouse",  # Missing parameters and terminator (no comma after opcode)
            None,  # None input
            123,  # Non-string input
        ]

        for message in malformed_messages:
            result = is_user_activity(message)
            assert result is False, f"Should return False for malformed message: {message}"

    def test_truncated_activity_message_still_detected(self):
        """A truncated mouse/key instruction is still user activity."""
        assert is_user_activity("5.mouse,3.100,3.200") is True
        assert is_user_activity("3.key,2.65") is True

    def test_only_non_input_events_are_passive(self):
        """Verify non-input protocol events do not reset the idle timeout."""
        passive_events = [
            "4.size,4.1280,4.1024;",
            "4.size,4.1920,4.1080;",
            "4.sync,3.456;",
            "3.nop;",
        ]

        for event in passive_events:
            result = is_user_activity(event)
            assert result is False, f"Event '{event}' should be passive"

    def test_input_events_are_active(self):
        """Verify real user-input instructions are considered activity."""
        active_events = [
            "5.mouse,3.100,3.200,1.0;",  # Mouse move
            "5.mouse,2.50,2.50,1.1;",  # Mouse click
            "3.key,2.32,1.1;",  # Key press
            "3.key,2.32,1.0;",  # Key release
        ]

        for event in active_events:
            result = is_user_activity(event)
            assert result is True, f"Event '{event}' should be active"
