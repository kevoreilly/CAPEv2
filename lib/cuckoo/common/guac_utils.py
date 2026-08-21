"""Utilities for Guacamole protocol handling and activity detection."""

import re

# Matches the opcode of a Guacamole instruction at message start or after ';'.
# Guacamole wire format: <len>.<value>,<len>.<value>...;
# Example: 5.mouse,3.100,3.200,1.0;
_ACTIVITY_RE = re.compile(r"(?:^|;)\d+\.(key|mouse),")


def is_user_activity(message: str) -> bool:
    """Return ``True`` if *message* contains a mouse or keyboard instruction."""
    if not message or not isinstance(message, str):
        return False
    return _ACTIVITY_RE.search(message) is not None
