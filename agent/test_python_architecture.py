"""Ensure our version check and architecture check function as desired."""

import sys

import pytest


def test_32_bit(monkeypatch):
    with monkeypatch.context() as m:
        # Unload "agent" module if previously imported.
        sys.modules.pop("agent", None)
        m.setattr(sys, "maxsize", 2**64)
        m.setattr(sys, "platform", "win32")
        with pytest.raises(SystemExit):
            # Should raise an exception.
            import agent  # noqa: F401


def test_python_version(monkeypatch):
    with monkeypatch.context() as m:
        # Unload "agent" module if previously imported.
        sys.modules.pop("agent", None)
        m.setattr(sys, "version_info", (3, 2, 1, "final", 0))
        with pytest.raises(SystemExit):
            # Should raise an exception.
            import agent  # noqa: F401
