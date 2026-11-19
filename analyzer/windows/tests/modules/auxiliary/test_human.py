"""Tests for modules.auxiliary.human monotonic clock scheduling, MUI, Win32, and UIA."""

import ctypes
import random
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
            patch.object(human_mod, "MUI_CLICK_BUTTONS", ("aceptar", "はい", "是", "예")),
            patch.object(human_mod, "MUI_DONT_CLICK_BUTTONS", ("cancelar",)),
        ):
            # Positive matches (including localized MUI, Win32 mnemonics, and UIA-stripped CJK mnemonics)
            self.assertTrue(human_mod.should_click_button("&Next >"))
            self.assertTrue(human_mod.should_click_button("Enable Editing"))
            self.assertTrue(human_mod.should_click_button("Run anyway"))
            self.assertTrue(human_mod.should_click_button("Run (64-bit)"))
            self.assertTrue(human_mod.should_click_button("Aceptar"))
            self.assertTrue(human_mod.should_click_button("はい(&Y)"))
            self.assertTrue(human_mod.should_click_button("はい(Y)"))
            self.assertTrue(human_mod.should_click_button("是"))
            self.assertTrue(human_mod.should_click_button("是(Y)"))
            self.assertTrue(human_mod.should_click_button("是（Y）"))
            self.assertTrue(human_mod.should_click_button("예(Y)"))

            # Negative matches: word boundaries avoid false positives on substrings
            self.assertFalse(human_mod.should_click_button("Uninstall"))
            self.assertFalse(human_mod.should_click_button("Bookmark"))
            self.assertFalse(human_mod.should_click_button("Outlook"))
            self.assertFalse(human_mod.should_click_button("JavaScript"))
            self.assertFalse(human_mod.should_click_button("Endnote"))
            self.assertFalse(human_mod.should_click_button("Disagree"))
            self.assertFalse(human_mod.should_click_button("不是"))
            self.assertFalse(human_mod.should_click_button("不是(N)"))

            # Dont-click overrides click
            self.assertFalse(human_mod.should_click_button("Don't run"))
            self.assertFalse(human_mod.should_click_button("Cancelar"))

            # App main frame exclusion list skips Ribbon/toolbar chrome while allowing Enable Content
            self.assertFalse(human_mod.should_click_button("Save", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS))
            self.assertFalse(human_mod.should_click_button("Open", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS))
            self.assertFalse(human_mod.should_click_button("Next Slide", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS))
            self.assertFalse(human_mod.should_click_button("Accept", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS))
            self.assertTrue(
                human_mod.should_click_button("Enable Content", excluded=human_mod.OFFICE_FRAME_EXCLUDED_UIA_BUTTONS)
            )


class TestHumanWin32StyleAndDocumentFixes(unittest.TestCase):
    def test_win32_button_class_checkbox_radio_and_groupbox_classification(self):
        # Standard Win32 / NSIS / MSI controls share class "Button" and differ by BS_TYPEMASK.
        hwnd_checkbox = 0x101
        hwnd_radio = 0x102
        hwnd_push = 0x103
        hwnd_groupbox = 0x104
        styles = {
            hwnd_checkbox: human_mod.BS_AUTOCHECKBOX,
            hwnd_radio: human_mod.BS_AUTORADIOBUTTON,
            hwnd_push: 0x00000000,  # BS_PUSHBUTTON
            hwnd_groupbox: human_mod.BS_GROUPBOX,
        }

        with patch.object(human_mod, "USER32") as user32:
            user32.GetWindowLongW.side_effect = lambda h, idx: styles[h]
            self.assertTrue(human_mod.is_checkbox("button", hwnd_checkbox))
            self.assertFalse(human_mod.is_radio_button("button", hwnd_checkbox))
            self.assertTrue(human_mod.is_radio_button("button", hwnd_radio))
            self.assertFalse(human_mod.is_checkbox("button", hwnd_push))
            self.assertFalse(human_mod.is_radio_button("button", hwnd_push))
            self.assertTrue(human_mod.is_button("button", hwnd_push))
            self.assertFalse(human_mod.is_button("button", hwnd_groupbox))

    def test_already_checked_nsis_license_checkbox_and_groupbox_advance_to_next_button(self):
        hwnd_group = 0x200
        hwnd_accept = 0x201
        hwnd_next = 0x202
        clicked = []

        def fake_get_class(hwnd, buf, _size):
            buf.value = "Button"
            return len(buf.value)

        styles = {hwnd_group: human_mod.BS_GROUPBOX, hwnd_accept: human_mod.BS_AUTOCHECKBOX, hwnd_next: 0x0}
        texts = {
            hwnd_group: "Install options",
            hwnd_accept: "I &accept the terms of the License Agreement",
            hwnd_next: "&Next >",
        }

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

            # Group box must be skipped without clicking or stopping enumeration.
            self.assertTrue(human_mod.interact_with_window(hwnd_group, 0))
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

    def test_get_document_window_click_around_ignores_non_document_windows_and_matches_modern_office(self):
        titles = {
            0x310: "Program Manager",
            0x311: "report.docx - Word",
            0x312: "lure.pdf - Adobe Acrobat Reader DC",
            0x313: "budget.xlsx - Excel",
            0x314: "slides.pptx - PowerPoint",
        }

        def fake_get_window_text(hwnd, buf, _size):
            buf.value = titles[hwnd]
            return len(buf.value)

        with (
            patch.object(human_mod, "RESOLUTION", {"x": 1920, "y": 1080}),
            patch.object(human_mod, "RESOLUTION_WITHOUT_TASKBAR", {"x": 1920, "y": 1040}),
            patch.object(human_mod, "DOCUMENT_WINDOW_CLICK_AROUND", False),
            patch.object(human_mod, "click_around") as click_around,
            patch.object(human_mod, "USER32") as user32,
            patch.object(human_mod, "KERNEL32") as kernel32,
        ):
            user32.IsWindowVisible.return_value = True
            user32.GetWindowTextW.side_effect = fake_get_window_text

            # Non-document window must not click, sleep, or set DOCUMENT_WINDOW_CLICK_AROUND.
            self.assertTrue(human_mod.get_document_window_click_around(0x310, 0))
            click_around.assert_not_called()
            kernel32.Sleep.assert_not_called()
            self.assertFalse(human_mod.DOCUMENT_WINDOW_CLICK_AROUND)

            # Modern Word title ("- Word") triggers click_around, sleeps once, and marks done.
            self.assertTrue(human_mod.get_document_window_click_around(0x311, 0))
            click_around.assert_called_once_with(0x311, (0, 1920), (300, 1040))
            kernel32.Sleep.assert_called_once_with(20000)
            self.assertTrue(human_mod.DOCUMENT_WINDOW_CLICK_AROUND)

            # Subsequent enumerated windows must not click or sleep again once done.
            self.assertTrue(human_mod.get_document_window_click_around(0x312, 0))
            click_around.assert_called_once()
            kernel32.Sleep.assert_called_once()

        # Verify Excel/PowerPoint modern titles and low-resolution clamping (no inverted range).
        with (
            patch.object(human_mod, "RESOLUTION", {"x": 800, "y": 600}),
            patch.object(human_mod, "RESOLUTION_WITHOUT_TASKBAR", {"x": 800, "y": 560}),
            patch.object(human_mod, "DOCUMENT_WINDOW_CLICK_AROUND", False),
            patch.object(human_mod, "click_around") as click_around,
            patch.object(human_mod, "USER32") as user32,
            patch.object(human_mod, "KERNEL32"),
        ):
            user32.IsWindowVisible.return_value = True
            user32.GetWindowTextW.side_effect = fake_get_window_text

            self.assertTrue(human_mod.get_document_window_click_around(0x313, 0))
            click_around.assert_called_once_with(0x313, (0, 800), (400, 560))

            human_mod.DOCUMENT_WINDOW_CLICK_AROUND = False
            click_around.reset_mock()
            self.assertTrue(human_mod.get_document_window_click_around(0x314, 0))
            click_around.assert_called_once_with(0x314, (300, 800), (560, 560))

    def test_get_random_click_coords_keeps_documents_in_body_without_edge_pileup(self):
        rng = random.Random(42)
        with (
            patch.object(human_mod, "RESOLUTION_WITHOUT_TASKBAR", {"x": 1920, "y": 1040}),
            patch.object(human_mod, "random", rng),
        ):
            doc_pts = [human_mod.get_random_click_coords(doc=True) for _ in range(200)]
            non_doc_pts = [human_mod.get_random_click_coords(doc=False) for _ in range(50)]

        xs = [x for x, _ in doc_pts]
        ys = [y for _, y in doc_pts]
        self.assertTrue(all(480 <= x <= 1440 for x in xs))
        self.assertTrue(all(260 <= y <= 1040 for y in ys))
        # Uniform body sampling spreads clicks instead of piling ~80% onto y == H // 4.
        self.assertGreater(len(set(ys)), 50)
        self.assertLess(sum(y == 260 for y in ys), 10)
        # Non-document samples retain the original top-left-skewed distribution.
        self.assertTrue(any(y < 260 for _, y in non_doc_pts))
        self.assertTrue(any(x < 480 for x, _ in non_doc_pts))

    def test_human_run_random_click_branch_uses_document_body_coords(self):
        cfg = MagicMock()
        cfg.human_windows = True
        cfg.file_type = "PDF document, version 1.7"
        cfg.file_name = "invoice.pdf"

        h = Human(options={"nouia": "1"}, config=cfg)
        clicked_coords = []

        def fake_move(x, y):
            clicked_coords.append((x, y))

        def fake_sleep(_ms):
            h.do_run = False

        # First randint(0, 10) -> randoff=0, second randint(0, 7) -> rng=4 (random click branch),
        # then get_random_click_coords(doc=True) calls randint for x and y.
        randint_calls = iter([0, 4, 900, 620])
        randint_bounds = []

        def fake_randint(a, b):
            randint_bounds.append((a, b))
            return next(randint_calls)

        with (
            patch.object(human_mod, "RESOLUTION_WITHOUT_TASKBAR", {"x": 1920, "y": 1040}),
            patch.object(human_mod.random, "randint", side_effect=fake_randint),
            patch.object(human_mod, "populate_clipboard"),
            patch.object(human_mod, "refresh_mui_button_strings"),
            patch.object(human_mod, "move_mouse_realistically", side_effect=fake_move),
            patch.object(human_mod, "move_mouse_random"),
            patch.object(human_mod, "cursor_over_console_window", return_value=False),
            patch.object(human_mod, "click_mouse") as click_mouse,
            patch.object(human_mod, "EnumWindowsProc", side_effect=lambda fn: fn),
            patch.object(human_mod, "INITIAL_HWNDS", []),
            patch.object(human_mod, "USER32"),
            patch.object(human_mod, "KERNEL32") as kernel32,
        ):
            kernel32.Sleep.side_effect = fake_sleep
            h.run()

        self.assertEqual([(0, 10), (0, 7), (480, 1440), (260, 1040)], randint_bounds)
        self.assertEqual([(900, 620)], clicked_coords)
        click_mouse.assert_called_once()

    def test_send_message_timeout_reads_text_and_handles_hung_or_error_window(self):
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

        # Unsigned LRESULT(-1) from WM_GETTEXTLENGTH is rejected instead of allocating 4096 wchars.
        def fake_negative_lresult(_hwnd, msg, _wparam, _lparam, _flags, _timeout_ms, out_ptr):
            res = ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_size_t))
            res[0] = (1 << (ctypes.sizeof(ctypes.c_size_t) * 8)) - 1
            return 1

        with patch.object(human_mod, "USER32") as user32:
            user32.SendMessageTimeoutW.side_effect = fake_negative_lresult
            self.assertEqual("", human_mod.get_window_text(0x401))


class TestHumanUIAIntegration(unittest.TestCase):
    def test_handle_window_interaction_falls_back_to_uia_and_respects_app_frame_filter(self):
        fake_uia = MagicMock()
        fake_uia.available = True
        captured = {}

        def fake_interact(hwnd, match_fn, click_point_fn=None, *, include_hyperlinks=True):
            captured["hwnd"] = hwnd
            captured["include_hyperlinks"] = include_hyperlinks
            captured["save"] = match_fn("Save")
            captured["next"] = match_fn("Next Page")
            captured["accept"] = match_fn("Accept")
            captured["enable"] = match_fn("Enable Editing")
            return True

        fake_uia.interact_with_hwnd.side_effect = fake_interact

        for cls_name in ("OpusApp", "AcrobatSDIWindow"):
            captured.clear()

            def fake_get_class(_hwnd, buf, _size, _cls=cls_name):
                buf.value = _cls
                return len(buf.value)

            with (
                patch.object(human_mod, "UIA_CLIENT", fake_uia),
                patch.object(human_mod, "INITIAL_HWNDS", [0x999]),
                patch.object(human_mod, "EnumChildProc", side_effect=lambda fn: fn),
                patch.object(human_mod, "USER32") as user32,
            ):
                user32.IsWindowVisible.return_value = True
                user32.IsIconic.return_value = False
                user32.GetClassNameW.side_effect = fake_get_class
                user32.EnumChildWindows.return_value = True

                human_mod.handle_window_interaction(0x501, 0)

            self.assertEqual(0x501, captured["hwnd"])
            self.assertFalse(captured["include_hyperlinks"])
            self.assertFalse(captured["save"])
            self.assertFalse(captured["next"])
            self.assertFalse(captured["accept"])
            self.assertTrue(captured["enable"])

    def test_uia_prefers_explicit_click_on_nuidialog_before_blind_enter_fallback(self):
        fake_uia = MagicMock()
        fake_uia.available = True
        fake_uia.interact_with_hwnd.return_value = True

        def fake_get_class(_hwnd, buf, _size):
            buf.value = "NUIDialog"
            return len(buf.value)

        with (
            patch.object(human_mod, "UIA_CLIENT", fake_uia),
            patch.object(human_mod, "INITIAL_HWNDS", []),
            patch.object(human_mod, "USER32") as user32,
        ):
            user32.IsWindowVisible.return_value = True
            user32.IsIconic.return_value = False
            user32.GetClassNameW.side_effect = fake_get_class

            human_mod.handle_window_interaction(0x601, 0)

        fake_uia.interact_with_hwnd.assert_called_once()
        user32.keybd_event.assert_not_called()

        # When UIA finds nothing on NUIDialog, legacy Enter fallback still executes once (no double UIA call).
        fake_uia.interact_with_hwnd.reset_mock()
        fake_uia.interact_with_hwnd.return_value = False
        with (
            patch.object(human_mod, "UIA_CLIENT", fake_uia),
            patch.object(human_mod, "INITIAL_HWNDS", []),
            patch.object(human_mod, "get_window_text", return_value="Microsoft Office Security Notice"),
            patch.object(human_mod, "USER32") as user32,
        ):
            user32.IsWindowVisible.return_value = True
            user32.IsWindowEnabled.return_value = True
            user32.IsIconic.return_value = False
            user32.GetClassNameW.side_effect = fake_get_class

            human_mod.handle_window_interaction(0x601, 0)

        fake_uia.interact_with_hwnd.assert_called_once()
        self.assertEqual(2, user32.keybd_event.call_count)

    def test_uia_skips_initial_hwnds_shell_browsers_explorer_and_minimized_windows(self):
        fake_uia = MagicMock()
        fake_uia.available = True

        for skip_class in (
            "Shell_TrayWnd",
            "CabinetWClass",
            "Chrome_WidgetWin_1",
            "MozillaWindowClass",
            "Windows.UI.Core.CoreWindow",
            "CASCADIA_HOSTING_WINDOW_CLASS",
        ):
            def fake_get_class(_hwnd, buf, _size, _cls=skip_class):
                buf.value = _cls
                return len(buf.value)

            with (
                patch.object(human_mod, "INITIAL_HWNDS", [0x111]),
                patch.object(human_mod, "USER32") as user32,
            ):
                user32.IsWindowVisible.return_value = True
                user32.IsIconic.return_value = False
                user32.GetClassNameW.side_effect = fake_get_class

                self.assertFalse(human_mod.interact_with_window_uia(0x111, fake_uia))
                self.assertFalse(human_mod.interact_with_window_uia(0x222, fake_uia))

        # Minimized (iconic) dialog is skipped even though IsWindowVisible returns True.
        def fake_dialog_class(_hwnd, buf, _size):
            buf.value = "#32770"
            return len(buf.value)

        with (
            patch.object(human_mod, "INITIAL_HWNDS", []),
            patch.object(human_mod, "USER32") as user32,
        ):
            user32.IsWindowVisible.return_value = True
            user32.IsIconic.return_value = True
            user32.GetClassNameW.side_effect = fake_dialog_class
            self.assertFalse(human_mod.interact_with_window_uia(0x333, fake_uia))

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
