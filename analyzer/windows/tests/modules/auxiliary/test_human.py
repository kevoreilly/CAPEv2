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


class TestHumanMUIAndMatching(unittest.TestCase):
    def test_load_mui_button_strings_normalizes_western_and_cjk_mnemonics(self):
        localized = {
            800: "Aceptar",
            801: "&Cancelar",
            802: "Anular(&A)",
            803: "&Reintentar",
            805: "はい(&Y)",
            808: "Ayuda",
            809: "再試行(&R)",
            810: "&Continuar",
        }

        def fake_load_string(hmod, res_id, buf, size):
            val = localized.get(res_id, "")
            if not val:
                return 0
            buf.value = val
            return len(val)

        with (
            patch.object(human_mod, "KERNEL32") as kernel32,
            patch.object(human_mod, "USER32") as user32,
        ):
            kernel32.GetModuleHandleW.return_value = 0x76000000
            user32.LoadStringW.side_effect = fake_load_string

            clicks, dont_clicks = human_mod.load_mui_button_strings()

        self.assertEqual(("aceptar", "reintentar", "はい", "再試行", "continuar"), clicks)
        self.assertEqual(("cancelar", "anular", "ayuda"), dont_clicks)

    def test_should_click_button_uses_word_boundaries_and_mui_strings(self):
        with (
            patch.object(human_mod, "MUI_CLICK_BUTTONS", ("aceptar", "はい", "是")),
            patch.object(human_mod, "MUI_DONT_CLICK_BUTTONS", ("cancelar",)),
        ):
            # Positive matches (including localized MUI and mnemonics)
            self.assertTrue(human_mod.should_click_button("&Next >"))
            self.assertTrue(human_mod.should_click_button("Enable Editing"))
            self.assertTrue(human_mod.should_click_button("Run anyway"))
            self.assertTrue(human_mod.should_click_button("Aceptar"))
            self.assertTrue(human_mod.should_click_button("はい(&Y)"))
            self.assertTrue(human_mod.should_click_button("是"))

            # Negative matches: word boundaries avoid false positives on substrings
            self.assertFalse(human_mod.should_click_button("Uninstall"))
            self.assertFalse(human_mod.should_click_button("Bookmark"))
            self.assertFalse(human_mod.should_click_button("Outlook"))
            self.assertFalse(human_mod.should_click_button("JavaScript"))
            self.assertFalse(human_mod.should_click_button("Endnote"))
            self.assertFalse(human_mod.should_click_button("Disagree"))
            self.assertFalse(human_mod.should_click_button("不是"))

            # Dont-click overrides click
            self.assertFalse(human_mod.should_click_button("Don't run"))
            self.assertFalse(human_mod.should_click_button("Cancelar"))

            # Office main frame exclusion list skips Ribbon Save/Open while allowing Enable Content
            self.assertFalse(human_mod.should_click_button("Save", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS))
            self.assertFalse(human_mod.should_click_button("Open", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS))
            self.assertTrue(
                human_mod.should_click_button("Enable Content", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS)
            )


class TestHumanWin32StyleAndDocumentFixes(unittest.TestCase):
    def test_win32_button_class_checkbox_and_radio_route_to_check_button(self):
        # Standard Win32 / NSIS / MSI license checkbox uses class "Button" + BS_AUTOCHECKBOX style.
        hwnd_checkbox = 0x101
        hwnd_radio = 0x102
        hwnd_push = 0x103
        styles = {
            hwnd_checkbox: human_mod.BS_AUTOCHECKBOX,
            hwnd_radio: human_mod.BS_AUTORADIOBUTTON,
            hwnd_push: 0x00000000,  # BS_PUSHBUTTON
        }

        with patch.object(human_mod, "USER32") as user32:
            user32.GetWindowLongW.side_effect = lambda h, idx: styles[h]
            self.assertTrue(human_mod.is_checkbox("button", hwnd_checkbox))
            self.assertFalse(human_mod.is_radio_button("button", hwnd_checkbox))
            self.assertTrue(human_mod.is_radio_button("button", hwnd_radio))
            self.assertFalse(human_mod.is_checkbox("button", hwnd_push))
            self.assertFalse(human_mod.is_radio_button("button", hwnd_push))

    def test_already_checked_nsis_license_checkbox_advances_to_next_button(self):
        hwnd_accept = 0x201
        hwnd_next = 0x202
        clicked = []

        def fake_get_class(hwnd, buf, _size):
            buf.value = "Button"
            return len(buf.value)

        styles = {hwnd_accept: human_mod.BS_AUTOCHECKBOX, hwnd_next: 0x0}
        texts = {hwnd_accept: "I &accept the terms of the License Agreement", hwnd_next: "&Next >"}

        with (
            patch.object(human_mod, "USER32") as user32,
            patch.object(human_mod, "get_window_text", side_effect=lambda h: texts[h]),
            patch.object(human_mod, "is_button_checked", side_effect=lambda h: h == hwnd_accept),
            patch.object(human_mod, "send_click", side_effect=lambda h: clicked.append(h)),
        ):
            user32.IsWindowVisible.return_value = True
            user32.IsWindowEnabled.return_value = True
            user32.GetClassNameW.side_effect = fake_get_class
            user32.GetWindowLongW.side_effect = lambda h, _idx: styles[h]

            # Already-checked checkbox must return True (keep enumerating) without toggling off.
            self.assertTrue(human_mod.interact_with_window(hwnd_accept, 0))
            # Enumeration then reaches Next and clicks it, returning False to stop.
            self.assertFalse(human_mod.interact_with_window(hwnd_next, 0))

        self.assertEqual([hwnd_next], clicked)

    def test_get_document_window_click_around_uses_lowercase_resolution_keys(self):
        def fake_get_window_text(_hwnd, buf, _size):
            buf.value = "Sample - Microsoft Word"
            return len(buf.value)

        with (
            patch.object(human_mod, "RESOLUTION", {"x": 1280, "y": 720}),
            patch.object(human_mod, "RESOLUTION_WITHOUT_TASKBAR", {"x": 1280, "y": 680}),
            patch.object(human_mod, "DOCUMENT_WINDOW_CLICK_AROUND", False),
            patch.object(human_mod, "click_around") as click_around,
            patch.object(human_mod, "USER32") as user32,
            patch.object(human_mod, "KERNEL32"),
        ):
            user32.IsWindowVisible.return_value = True
            user32.GetWindowTextW.side_effect = fake_get_window_text

            self.assertTrue(human_mod.get_document_window_click_around(0x301, 0))

        click_around.assert_called_once_with(0x301, (0, 1280), (300, 680))

    def test_send_message_timeout_reads_text_and_handles_hung_window(self):
        def fake_send_timeout(_hwnd, msg, _wparam, lparam, flags, timeout_ms, out_ptr):
            self.assertEqual(human_mod.SMTO_ABORTIFHUNG, flags)
            self.assertEqual(human_mod.SEND_MESSAGE_TIMEOUT_MS, timeout_ms)
            res = ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_size_t))
            if msg == human_mod.WM_GETTEXTLENGTH:
                res[0] = len("&Install")
                return 1
            if msg == human_mod.WM_GETTEXT:
                lparam.value = "&Install"
                res[0] = len("&Install")
                return 1
            if msg == human_mod.BM_GETCHECK:
                res[0] = human_mod.BST_CHECKED
                return 1
            return 0

        with patch.object(human_mod, "USER32") as user32:
            user32.SendMessageTimeoutW.side_effect = fake_send_timeout
            self.assertEqual("Install", human_mod.get_window_text(0x401))
            self.assertTrue(human_mod.is_button_checked(0x401))

        # Hung window (SendMessageTimeoutW returns 0) degrades safely instead of blocking.
        with patch.object(human_mod, "USER32") as user32:
            user32.SendMessageTimeoutW.return_value = 0
            self.assertEqual("", human_mod.get_window_text(0x401))
            self.assertFalse(human_mod.is_button_checked(0x401))


class TestHumanUIAIntegration(unittest.TestCase):
    def test_handle_window_interaction_falls_back_to_uia_and_respects_office_frame_filter(self):
        fake_uia = MagicMock()
        fake_uia.available = True
        captured = {}

        def fake_interact(hwnd, match_fn, click_point_fn=None):
            captured["hwnd"] = hwnd
            captured["save"] = match_fn("Save")
            captured["enable"] = match_fn("Enable Editing")
            return True

        fake_uia.interact_with_hwnd.side_effect = fake_interact

        def fake_get_class(_hwnd, buf, _size):
            buf.value = "OpusApp"
            return len(buf.value)

        with (
            patch.object(human_mod, "UIA_CLIENT", fake_uia),
            patch.object(human_mod, "INITIAL_HWNDS", [0x999]),
            patch.object(human_mod, "EnumChildProc", side_effect=lambda fn: fn),
            patch.object(human_mod, "USER32") as user32,
        ):
            user32.IsWindowVisible.return_value = True
            user32.GetClassNameW.side_effect = fake_get_class
            user32.EnumChildWindows.return_value = True

            human_mod.handle_window_interaction(0x501, 0)

        self.assertEqual(0x501, captured["hwnd"])
        self.assertFalse(captured["save"])
        self.assertTrue(captured["enable"])

    def test_uia_skips_initial_hwnds_and_shell_windows(self):
        fake_uia = MagicMock()
        fake_uia.available = True

        def fake_get_class(_hwnd, buf, _size):
            buf.value = "Shell_TrayWnd"
            return len(buf.value)

        with (
            patch.object(human_mod, "INITIAL_HWNDS", [0x111]),
            patch.object(human_mod, "USER32") as user32,
        ):
            user32.IsWindowVisible.return_value = True
            user32.GetClassNameW.side_effect = fake_get_class

            self.assertFalse(human_mod.interact_with_window_uia(0x111, fake_uia))
            self.assertFalse(human_mod.interact_with_window_uia(0x222, fake_uia))

        fake_uia.interact_with_hwnd.assert_not_called()

    def test_nouia_option_skips_uia_initialization(self):
        cfg = MagicMock()
        cfg.human_windows = True
        cfg.file_type = ""
        cfg.file_name = "sample.exe"

        h = Human(options={"nouia": "1"}, config=cfg)
        h.do_run = False

        with (
            patch.object(human_mod, "populate_clipboard"),
            patch.object(human_mod, "refresh_mui_button_strings") as refresh_mui,
            patch.object(human_mod, "UIAClient") as uia_cls,
            patch.object(human_mod, "EnumWindowsProc", side_effect=lambda fn: fn),
            patch.object(human_mod, "USER32"),
        ):
            h.run()

        refresh_mui.assert_called_once()
        uia_cls.assert_not_called()

        # nouia=0 keeps UIA enabled.
        h_enabled = Human(options={"nouia": "0"}, config=cfg)
        h_enabled.do_run = False
        fake_uia = MagicMock()
        fake_uia.initialize.return_value = True
        with (
            patch.object(human_mod, "populate_clipboard"),
            patch.object(human_mod, "refresh_mui_button_strings"),
            patch.object(human_mod, "UIAClient", return_value=fake_uia),
            patch.object(human_mod, "EnumWindowsProc", side_effect=lambda fn: fn),
            patch.object(human_mod, "USER32"),
        ):
            h_enabled.run()

        fake_uia.initialize.assert_called_once()
        fake_uia.close.assert_called_once()

    def test_uia_client_closed_in_finally_on_exit(self):
        cfg = MagicMock()
        cfg.human_windows = True
        cfg.file_type = ""
        cfg.file_name = "sample.exe"

        h = Human(options={}, config=cfg)
        h.do_run = False
        fake_uia = MagicMock()
        fake_uia.initialize.return_value = True

        with (
            patch.object(human_mod, "populate_clipboard"),
            patch.object(human_mod, "refresh_mui_button_strings"),
            patch.object(human_mod, "UIAClient", return_value=fake_uia),
            patch.object(human_mod, "EnumWindowsProc", side_effect=lambda fn: fn),
            patch.object(human_mod, "USER32"),
        ):
            h.run()

        fake_uia.initialize.assert_called_once()
        fake_uia.close.assert_called_once()
        self.assertIsNone(human_mod.UIA_CLIENT)


if __name__ == "__main__":
    unittest.main()
