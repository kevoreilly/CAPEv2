"""Tests for modules.auxiliary.human monotonic clock scheduling."""

import ctypes
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
import os

os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

from modules.auxiliary import human as human_mod
from modules.auxiliary.human import Human


class TestHumanClockScheduling(unittest.TestCase):
    def test_document_check_and_window_switch_follow_monotonic_clock(self):
        cfg = MagicMock()
        cfg.human_windows = True
        cfg.file_type = "Rich Text Format"
        cfg.file_name = "lure.rtf"

        h = Human(options={}, config=cfg)

        # Simulate monotonic clock advancing:
        # - initial setup at t=100.0 (next_document_check=160.0, next_window_switch=100.0)
        # - iteration 1 starts at t=100.0 -> window switch fires (next_window_switch=100.0 + 15 + 0 = 115.0), doc check does not
        # - iteration 2 starts at t=165.0 (e.g. after slow mouse movement) -> both doc check and window switch fire, then stop
        clock_values = iter([100.0, 100.0, 100.0, 100.0, 165.0, 165.0, 165.0])

        enum_callbacks = []

        def fake_enum_windows(cb, lparam):
            enum_callbacks.append(cb)
            return True

        def fake_sleep(ms):
            # Stop after the second loop iteration
            if len(enum_callbacks) >= 5:
                h.do_run = False

        with (
            patch.object(human_mod.time, "monotonic", side_effect=lambda: next(clock_values, 165.0)),
            patch.object(human_mod.random, "randint", return_value=0),
            patch.object(human_mod, "populate_clipboard"),
            patch.object(human_mod, "EnumWindowsProc", side_effect=lambda fn: fn),
            patch.object(human_mod, "INITIAL_HWNDS", [101, 202]),
            patch.object(human_mod, "DOCUMENT_WINDOW_CLICK_AROUND", False),
            patch.object(human_mod, "CLOSED_DOCUMENT_WINDOW", False),
            patch.object(human_mod, "USER32") as user32,
            patch.object(human_mod, "KERNEL32") as kernel32,
        ):
            user32.EnumWindows.side_effect = fake_enum_windows
            user32.GetForegroundWindow.return_value = 101
            kernel32.Sleep.side_effect = fake_sleep

            h.run()

        # Verify document window callbacks ran on the second iteration once monotonic clock passed +60s
        self.assertIn(human_mod.get_document_window_click_around, enum_callbacks)
        self.assertIn(human_mod.get_document_window, enum_callbacks)
        self.assertEqual(2, user32.SetForegroundWindow.call_count)


if __name__ == "__main__":
    unittest.main()
