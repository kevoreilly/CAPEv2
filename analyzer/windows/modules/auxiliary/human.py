#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import random
import time
import math
import re
import traceback
from ctypes import POINTER, WINFUNCTYPE, byref, c_bool, c_int, c_size_t, c_ssize_t, c_void_p, create_unicode_buffer, memmove, sizeof, wintypes
from datetime import datetime, timedelta
from math import floor
from threading import Thread

from lib.api.uia import UIAClient
from lib.common.abstracts import Auxiliary
from lib.common.defines import (
    BM_CLICK,
    BM_GETCHECK,
    BM_SETCHECK,
    BS_3STATE,
    BS_AUTO3STATE,
    BS_AUTOCHECKBOX,
    BS_AUTORADIOBUTTON,
    BS_CHECKBOX,
    BS_GROUPBOX,
    BS_RADIOBUTTON,
    BS_TYPEMASK,
    BST_CHECKED,
    GMEM_MOVEABLE,
    GWL_STYLE,
    KERNEL32,
    SMTO_ABORTIFHUNG,
    USER32,
    WM_CLOSE,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
)

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
EnumChildProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

CURSOR_POSITION_REGEX = r"\((\d+):(\d+)\)"
WAIT_REGEX = r"WAIT(\d+)"
INTERVAL_REGEX = r"INTERVAL(\d+)"

# Enums for mouse instruction commands
CLICK_CMD = "click"
INTERVAL_CMD = "interval"
STOP_CMD = "stop"
WAIT_CMD = "wait"

SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_CXFULLSCREEN = 16
SM_CYFULLSCREEN = 17
RESOLUTION = {"x": USER32.GetSystemMetrics(SM_CXSCREEN), "y": USER32.GetSystemMetrics(SM_CYSCREEN)}
RESOLUTION_WITHOUT_TASKBAR = {"x": USER32.GetSystemMetrics(SM_CXFULLSCREEN), "y": USER32.GetSystemMetrics(SM_CYFULLSCREEN)}

INITIAL_HWNDS = []
# This global constant will contain the list of mouse instructions to action on the task, if applicable
GIVEN_INSTRUCTIONS = []
CLOSED_DOCUMENT_WINDOW = False
DOCUMENT_WINDOW_CLICK_AROUND = False
CF_UNICODETEXT = 0x000D

# Define clipboard-related WinAPI signatures explicitly to avoid pointer truncation.
KERNEL32.GlobalAlloc.argtypes = [wintypes.UINT, c_size_t]
KERNEL32.GlobalAlloc.restype = wintypes.HGLOBAL
KERNEL32.GlobalLock.argtypes = [wintypes.HGLOBAL]
KERNEL32.GlobalLock.restype = wintypes.LPVOID
KERNEL32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
KERNEL32.GlobalUnlock.restype = wintypes.BOOL
USER32.OpenClipboard.argtypes = [wintypes.HWND]
USER32.OpenClipboard.restype = wintypes.BOOL
USER32.EmptyClipboard.argtypes = []
USER32.EmptyClipboard.restype = wintypes.BOOL
USER32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
USER32.SetClipboardData.restype = wintypes.HANDLE
USER32.CloseClipboard.argtypes = []
USER32.CloseClipboard.restype = wintypes.BOOL

# Explicit WinAPI prototypes for MUI loading, button style inspection, and timeout-bounded messaging.
KERNEL32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
KERNEL32.GetModuleHandleW.restype = wintypes.HMODULE
USER32.LoadStringW.argtypes = [wintypes.HINSTANCE, wintypes.UINT, wintypes.LPWSTR, c_int]
USER32.LoadStringW.restype = c_int
USER32.GetWindowLongW.argtypes = [wintypes.HWND, c_int]
USER32.GetWindowLongW.restype = wintypes.LONG
USER32.IsIconic.argtypes = [wintypes.HWND]
USER32.IsIconic.restype = wintypes.BOOL
USER32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND,
    wintypes.UINT,
    c_size_t,
    c_void_p,
    wintypes.UINT,
    wintypes.UINT,
    POINTER(c_size_t),
]
USER32.SendMessageTimeoutW.restype = c_ssize_t

SEND_MESSAGE_TIMEOUT_MS = 500
_MAX_SIGNED_SIZE_T = (1 << (sizeof(c_size_t) * 8 - 1)) - 1

# Standard user32.dll MUI string resource IDs (799 + IDOK..IDCONTINUE).
MUI_CLICK_RESOURCE_IDS = (
    800,  # OK
    803,  # Retry
    805,  # Yes
    809,  # Try Again
    810,  # Continue
)
MUI_DONT_CLICK_RESOURCE_IDS = (
    801,  # Cancel
    802,  # Abort
    808,  # Help
)
# Strip Western/CJK accelerator suffixes both with '&' (Win32 WM_GETTEXT / LoadStringW)
# and trailing '(X)' / '（X）' without '&' (Windows UIA HWND proxy strips '&' from Name).
MUI_ACCESS_KEY_RE = re.compile(r"\s*[\(\uff08]&[A-Za-z0-9][\)\uff09]|\s*[\(\uff08][A-Za-z0-9][\)\uff09](?=\s*$)")

MUI_CLICK_BUTTONS = ()
MUI_DONT_CLICK_BUTTONS = ()
UIA_CLIENT = None

WIN32_CHECKBOX_TYPES = (BS_CHECKBOX, BS_AUTOCHECKBOX, BS_3STATE, BS_AUTO3STATE)
WIN32_RADIO_TYPES = (BS_RADIOBUTTON, BS_AUTORADIOBUTTON)

UIA_SKIP_WINDOW_CLASSES = frozenset(
    {
        "cabinetwclass",
        "cascadia_hosting_window_class",
        "chrome_widgetwin_1",
        "consolewindowclass",
        "dv2controlhost",
        "mozillawindowclass",
        "notifyiconoverflowwindow",
        "progman",
        "shell_inputswitchtoplevelwindow",
        "shell_secondarytraywnd",
        "shell_traywnd",
        "tasklistthumbnailwnd",
        "toplevelwindowforoverflowxamlisland",
        "windows.ui.core.corewindow",
        "workerw",
        "xamlexplorerhostislandwindow",
    }
)
APP_MAIN_FRAME_CLASSES = frozenset(
    {
        "acrobatsdiwindow",
        "opusapp",
        "pptframeclass",
        "rctrl_renwnd32",
        "xlmain",
    }
)
OFFICE_MAIN_FRAME_CLASSES = APP_MAIN_FRAME_CLASSES
# Exclude permanent Ribbon / toolbar / chrome actions when inspecting an Office or
# document application main frame via UIA, while still allowing Protected View /
# Security Warning bar buttons ("Enable Editing", "Enable Content", etc.).
APP_FRAME_EXCLUDED_UIA_BUTTONS = frozenset(
    {
        "save",
        "open",
        "next",
        "accept",
        "end",
        "later",
        "finish",
        "keep",
        "connect",
        "speichern",
        "oeffnen",
        "öffnen",
        "weiter",
        "akzeptieren",
        "ende",
        "spaeter",
        "später",
        "fertig",
        "starten",
        "beenden",
        "senden",
        "schliessen",
    }
)
OFFICE_FRAME_EXCLUDED_UIA_BUTTONS = APP_FRAME_EXCLUDED_UIA_BUTTONS

CLICK_BUTTONS = (
    # english
    "yes",
    "ok",
    "accept",
    "next",
    "install",
    "run",
    "agree",
    "enable",
    "retry",
    "don't send",
    "don't save",
    "continue",
    "connect",
    "unzip",
    "open",
    "close the program",
    "save",
    "later",
    "finish",
    "end",
    "keep",
    "allow access",
    "remind me later",
    # german
    "ja",
    "weiter",
    "akzeptieren",
    "ende",
    "starten",
    "jetzt starten",
    "neustarten",
    "neu starten",
    "jetzt neu starten",
    "beenden",
    "oeffnen",
    "schliessen",
    "installation weiterfuhren",
    "fertig",
    "beenden",
    "fortsetzen",
    "fortfahren",
    "stimme zu",
    "zustimmen",
    "senden",
    "nicht senden",
    "speichern",
    "nicht speichern",
    "ausfuehren",
    "spaeter",
    "einverstanden",
    # ru
    "установить",
)

DONT_CLICK_BUTTONS = (
    # english
    "check online for a solution",
    "don't ask me again for remote connections from this publisher",
    "don't run",
    "do not ask again until the next update is available",
    "cancel",
    "do not accept the agreement",
    "i would like to help make reader even better",
    "restart now",
    # german
    "abbrechen",
    "online nach losung suchen",
    "abbruch",
    "nicht ausfuehren",
    "hilfe",
    "stimme nicht zu",
    # ru
    "приoстановить",
    "отмена",
)

OFFICE_WINDOW_CLASSES = (
    "nuidialog",
    "bosa_sdm_msword",
)


def get_cursor_position():
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    return {"x": pt.x, "y": pt.y}


def cursor_over_console_window():
    # Get current cursor position
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))

    # Get the window handle at the cursor position
    hwnd = USER32.WindowFromPoint(pt)

    if not hwnd:
        return False

    # Check if the window is visible
    if not USER32.IsWindowVisible(hwnd):
        return False

    # Get the window's class name
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    classname = str(classname_ptr.value)

    terminal_classes = ["ConsoleWindowClass",]
    return any(cls in classname for cls in terminal_classes)


def _is_cjk_text(text):
    return any(
        "\u2e80" <= ch <= "\u9fff" or "\u3040" <= ch <= "\u30ff" or "\uac00" <= ch <= "\ud7af"
        for ch in text
    )


def normalize_button_text(text):
    if not text:
        return ""
    cleaned = MUI_ACCESS_KEY_RE.sub("", text)
    return cleaned.replace("&", "").strip().lower()


def _matches_candidate(button_text, candidate):
    if not candidate:
        return False
    if len(candidate) == 1:
        return button_text == candidate
    if _is_cjk_text(candidate):
        return candidate in button_text
    return re.search(rf"(?<!\w){re.escape(candidate)}(?!\w)", button_text) is not None


def load_mui_button_strings():
    """Load localized standard dialog button labels from user32.dll via Windows MUI."""
    try:
        h_user32 = KERNEL32.GetModuleHandleW("user32.dll")
    except Exception as err:
        log.debug("Failed to obtain user32.dll handle for MUI strings: %s", err)
        return (), ()

    if not isinstance(h_user32, int) or not h_user32:
        return (), ()

    def _load_group(res_ids):
        loaded = []
        buf = create_unicode_buffer(128)
        for res_id in res_ids:
            try:
                length = USER32.LoadStringW(h_user32, res_id, buf, 128)
            except Exception as err:
                log.debug("LoadStringW failed for resource ID %d: %s", res_id, err)
                continue
            if isinstance(length, int) and length > 0:
                normalized = normalize_button_text(buf.value[:length])
                if normalized and normalized not in loaded:
                    loaded.append(normalized)
        return tuple(loaded)

    return _load_group(MUI_CLICK_RESOURCE_IDS), _load_group(MUI_DONT_CLICK_RESOURCE_IDS)


def refresh_mui_button_strings():
    global MUI_CLICK_BUTTONS
    global MUI_DONT_CLICK_BUTTONS
    MUI_CLICK_BUTTONS, MUI_DONT_CLICK_BUTTONS = load_mui_button_strings()
    if MUI_CLICK_BUTTONS or MUI_DONT_CLICK_BUTTONS:
        log.debug(
            "Loaded %d clickable and %d ignored Windows MUI dialog labels",
            len(MUI_CLICK_BUTTONS),
            len(MUI_DONT_CLICK_BUTTONS),
        )


def should_click_button(raw_text, excluded=None):
    button_text = normalize_button_text(raw_text)
    if not button_text:
        return False

    dont_click_candidates = DONT_CLICK_BUTTONS + MUI_DONT_CLICK_BUTTONS
    if any(_matches_candidate(button_text, text) for text in dont_click_candidates):
        return False

    click_candidates = CLICK_BUTTONS + MUI_CLICK_BUTTONS
    for text in click_candidates:
        if excluded and text in excluded:
            continue
        if _matches_candidate(button_text, text):
            return True
    return False


def _send_message_timeout(hwnd, msg, wparam=0, lparam=0, timeout_ms=SEND_MESSAGE_TIMEOUT_MS):
    result = c_size_t(0)
    ok = USER32.SendMessageTimeoutW(hwnd, msg, wparam, lparam, SMTO_ABORTIFHUNG, timeout_ms, byref(result))
    if not ok:
        return None
    return int(result.value)


def get_window_classname(hwnd):
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    return str(classname_ptr.value).lower()


def get_win32_button_type(hwnd):
    try:
        style = USER32.GetWindowLongW(hwnd, GWL_STYLE)
    except Exception:
        return None
    if not isinstance(style, int):
        return None
    return style & BS_TYPEMASK


def is_window_minimized(hwnd):
    try:
        iconic = USER32.IsIconic(hwnd)
    except Exception:
        return False
    return bool(isinstance(iconic, int) and iconic)


def get_window_text(hwnd):
    length = _send_message_timeout(hwnd, WM_GETTEXTLENGTH, 0, 0)
    if not length or length < 0 or length > _MAX_SIGNED_SIZE_T:
        return ""
    length = min(length, 4096)
    text = create_unicode_buffer(length + 1)
    if _send_message_timeout(hwnd, WM_GETTEXT, length + 1, text) is None:
        return ""
    return MUI_ACCESS_KEY_RE.sub("", text.value).replace("&", "")


def is_button_checked(hwnd):
    state = _send_message_timeout(hwnd, BM_GETCHECK, 0, 0)
    return bool(state == BST_CHECKED)


def send_click(hwnd):
    USER32.SetForegroundWindow(hwnd)
    KERNEL32.Sleep(1000)
    _send_message_timeout(hwnd, BM_CLICK, 0, 0)


def click_button(hwnd, classname):
    button_text = get_window_text(hwnd)
    if button_text == "":
        return True

    if not USER32.IsWindowEnabled(hwnd):
        # Ignore buttons that are disabled
        return True

    if "Microsoft" in button_text and classname in OFFICE_WINDOW_CLASSES:
        log.info("Issuing keypress on Office dialog")
        USER32.SetForegroundWindow(hwnd)
        # enter key down event
        USER32.keybd_event(0x0D, 0x1C, 0, 0)
        # enter key up event
        USER32.keybd_event(0x0D, 0x1C, 2, 0)
        return False

    # Check if the button is set as "clickable" and click it.
    normalized_text = normalize_button_text(button_text)
    if should_click_button(normalized_text):
        log.info('Found button "%s", clicking it', normalized_text)
        send_click(hwnd)
        # only stop searching when we click a button
        return False
    # continue searching through windows
    return True


def check_button(hwnd):
    if not USER32.IsWindowEnabled(hwnd):
        return True

    if is_button_checked(hwnd):
        return True

    button_text = normalize_button_text(get_window_text(hwnd))
    if should_click_button(button_text):
        log.info('Found checkable button "%s", checking it', button_text)
        # try clicking it first
        send_click(hwnd)
        if not is_button_checked(hwnd):
            # if it's still unchecked, check it
            _send_message_timeout(hwnd, BM_SETCHECK, BST_CHECKED, 0)
        # only stop searching when we click a checkbox
        return False
    # continue searching through windows
    return True


def is_button(classname, hwnd=None):
    if "button" in classname:
        if hwnd is not None and get_win32_button_type(hwnd) == BS_GROUPBOX:
            return False
        return True
    return classname in OFFICE_WINDOW_CLASSES


def is_checkbox(classname, hwnd=None):
    if "checkbox" in classname:
        return True
    if "button" in classname and hwnd is not None:
        return get_win32_button_type(hwnd) in WIN32_CHECKBOX_TYPES
    return False


def is_radio_button(classname, hwnd=None):
    if "radiobutton" in classname:
        return True
    if "button" in classname and hwnd is not None:
        return get_win32_button_type(hwnd) in WIN32_RADIO_TYPES
    return False


def interact_with_window(hwnd, lparam):
    # we don't want to bother clicking any non-visible child elements, as they
    # generally won't respond and will cause us to fixate on them for the
    # rest of the analysis, preventing progress with visible elements
    if not USER32.IsWindowVisible(hwnd):
        return True

    classname = get_window_classname(hwnd)

    if is_checkbox(classname, hwnd) or is_radio_button(classname, hwnd):
        return check_button(hwnd)
    elif is_button(classname, hwnd):
        return click_button(hwnd, classname)
    # continue searching through windows
    return True


def move_mouse_realistically(dest_x, dest_y):
    current_pos = get_cursor_position()
    start_x, start_y = current_pos['x'], current_pos['y']

    # Calculate distance to determine total duration
    distance = math.sqrt((dest_x - start_x)**2 + (dest_y - start_y)**2)
    if distance < 1:
        return

    # 1. Create random control points for a natural curve
    # These points 'pull' the path away from a perfect straight line
    # Offsetting these creates a unique arc every time
    offset = distance * 0.15
    ctrl_x1 = start_x + (dest_x - start_x) * 0.3 + random.uniform(-offset, offset)
    ctrl_y1 = start_y + (dest_y - start_y) * 0.3 + random.uniform(-offset, offset)
    ctrl_x2 = start_x + (dest_x - start_x) * 0.7 + random.uniform(-offset, offset)
    ctrl_y2 = start_y + (dest_y - start_y) * 0.7 + random.uniform(-offset, offset)

    steps = random.randint(30, 50) if distance < 500 else random.randint(60, 90)

    for i in range(steps + 1):
        t = i / steps

        # Cubic Bezier Formula for smooth pathing
        curr_x = int((1-t)**3 * start_x + 3*(1-t)**2 * t * ctrl_x1 +
                     3*(1-t) * t**2 * ctrl_x2 + t**3 * dest_x)
        curr_y = int((1-t)**3 * start_y + 3*(1-t)**2 * t * ctrl_y1 +
                     3*(1-t) * t**2 * ctrl_y2 + t**3 * dest_y)

        USER32.SetCursorPos(curr_x, curr_y)

        # 3. Speed Randomization (The "Human" Factor)
        # Base sleep + Sinusoidal deceleration + Gaussian noise (jitter)
        base_sleep = 0.001
        deceleration = (math.sin(t * math.pi) * 0.005) # Slower at start/end
        jitter = random.uniform(0, 0.003)              # Tiny random pauses

        # Occasional "Micro-hesitation" (1% chance to pause for a frame)
        if random.random() < 0.01:
            time.sleep(random.uniform(0.01, 0.03))

        time.sleep(base_sleep + deceleration + jitter)

    # Final snap to ensure precision
    USER32.SetCursorPos(dest_x, dest_y)


def _click_uia_point(hwnd, x, y):
    USER32.SetForegroundWindow(hwnd)
    move_mouse_realistically(x, y)
    if not cursor_over_console_window():
        click_mouse()


def interact_with_window_uia(hwnd, uia_client):
    if not uia_client or not uia_client.available:
        return False
    if hwnd in INITIAL_HWNDS or not USER32.IsWindowVisible(hwnd) or is_window_minimized(hwnd):
        return False

    top_classname = get_window_classname(hwnd)
    if top_classname in UIA_SKIP_WINDOW_CLASSES:
        return False

    is_app_frame = top_classname in APP_MAIN_FRAME_CLASSES
    excluded = APP_FRAME_EXCLUDED_UIA_BUTTONS if is_app_frame else None
    return uia_client.interact_with_hwnd(
        hwnd,
        match_fn=lambda text: should_click_button(text, excluded=excluded),
        click_point_fn=lambda x, y: _click_uia_point(hwnd, x, y),
        include_hyperlinks=not is_app_frame,
    )


# Callback procedure invoked for every enumerated window.
def handle_window_interaction(hwnd, lparam):
    uia_ready = UIA_CLIENT is not None and UIA_CLIENT.available
    top_classname = get_window_classname(hwnd) if uia_ready and USER32.IsWindowVisible(hwnd) else ""

    # On Office NetUI/SDM dialogs, prefer explicit UIA button invocation over a blind Enter keypress.
    if uia_ready and top_classname in OFFICE_WINDOW_CLASSES:
        if interact_with_window_uia(hwnd, UIA_CLIENT):
            return True

    # we also want to inspect the "parent" windows, not just the children
    acted = not interact_with_window(hwnd, lparam)
    if not acted:
        child_acted = [False]

        def _child_callback(child_hwnd, child_lparam):
            keep_going = interact_with_window(child_hwnd, child_lparam)
            if not keep_going:
                child_acted[0] = True
            return keep_going

        USER32.EnumChildWindows(hwnd, EnumChildProc(_child_callback), 0)
        acted = child_acted[0]

    if not acted and uia_ready and top_classname not in OFFICE_WINDOW_CLASSES:
        interact_with_window_uia(hwnd, UIA_CLIENT)
    return True


def get_window_list(hwnd, lparam):
    global INITIAL_HWNDS
    if USER32.IsWindowVisible(hwnd):
        INITIAL_HWNDS.append(hwnd)
    return True


def get_random_click_coords(doc=False):
    max_x = RESOLUTION_WITHOUT_TASKBAR["x"]
    max_y = RESOLUTION_WITHOUT_TASKBAR["y"]
    if doc:
        # Dividing by uniform(1, 16) puts 80% of draws in the top-left quarter, where
        # Acrobat's Home/Tools tabs and Office's File/Ribbon live (plus narrow side
        # panes like PowerPoint's slide rail and Acrobat's right Tools pane). Sample
        # uniformly across the central/lower document body instead.
        return (
            random.randint(max_x // 4, (max_x * 3) // 4),
            random.randint(max_y // 4, max_y),
        )
    return (
        int(max_x / random.uniform(1, 16)),
        int(max_y / random.uniform(1, 16)),
    )


def move_mouse_random():
    # To avoid mousing over desktop icons, use 1/4 of the total resolution as the starting pixel
    x = random.randint(RESOLUTION_WITHOUT_TASKBAR["x"] // 4, RESOLUTION_WITHOUT_TASKBAR["x"])
    y = random.randint(0, RESOLUTION_WITHOUT_TASKBAR["y"])

    # Originally was:
    # USER32.mouse_event(0x8000, x, y, 0, None)
    # Changed to SetCurorPos, since using GetCursorPos would not detect
    # the mouse events. This actually moves the cursor around which might
    # cause some unintended activity on the desktop. We might want to make
    # this featur optional.
    move_mouse_realistically(x, y)


def click_mouse():
    # Mouse down.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # Mouse up.
    USER32.mouse_event(4, 0, 0, 0, None)


def click_around(hwnd, workable_range_x, workable_range_y):
    USER32.SetForegroundWindow(hwnd)
    # first click the middle
    move_mouse_realistically(RESOLUTION["x"] // 2, RESOLUTION["y"] // 2)
    click_mouse()
    KERNEL32.Sleep(50)
    click_mouse()
    KERNEL32.Sleep(500)
    # click through the middle with offset for cell position on side and scroll bar
    if not GIVEN_INSTRUCTIONS:
        x = workable_range_x[0]
        while x < workable_range_x[1]:
            # make sure the window still exists
            if USER32.IsWindowVisible(hwnd):
                USER32.SetForegroundWindow(hwnd)
                move_mouse_realistically(x, RESOLUTION["y"] // 2)
                click_mouse()
                KERNEL32.Sleep(50)
                click_mouse()
                KERNEL32.Sleep(50)
                if not USER32.IsWindowVisible(hwnd):
                    break
                USER32.SetForegroundWindow(hwnd)
                move_mouse_realistically(x, random.randint(workable_range_y[0], workable_range_y[1]))
                click_mouse()
                KERNEL32.Sleep(50)
                click_mouse()
                KERNEL32.Sleep(50)
                if not USER32.IsWindowVisible(hwnd):
                    break
                USER32.SetForegroundWindow(hwnd)
                move_mouse_realistically(x, random.randint(workable_range_y[0], workable_range_y[1]))
                click_mouse()
                KERNEL32.Sleep(50)
                click_mouse()
                KERNEL32.Sleep(50)
                x += random.randint(150, 200)
                KERNEL32.Sleep(50)
            else:
                log.info("Breaking out of document window click loop as our window went away")
                break
    else:
        # We have instructions, now let's execute them!
        for instruction in GIVEN_INSTRUCTIONS:
            if USER32.IsWindowVisible(hwnd):
                USER32.SetForegroundWindow(hwnd)
                if instruction.lower() == CLICK_CMD:
                    click_mouse()
                else:
                    point = re.match(CURSOR_POSITION_REGEX, instruction)
                    if point and len(point.regs) == 3:
                        move_mouse_realistically(int(point.group(1)), int(point.group(2)))
                KERNEL32.Sleep(50)
            else:
                log.info("Breaking out of document window click loop as our window went away")
                break


def get_document_window_click_around(hwnd, lparm):
    # (0,0) left upper corner
    global DOCUMENT_WINDOW_CLICK_AROUND
    if DOCUMENT_WINDOW_CLICK_AROUND:
        return True
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        matched = False
        if any(
            value in text.value
            for value in (
                "Adobe",
                "Acrobat DC",
                "Acrobat",
                "Reader",
                "PDF",
            )
        ):
            # 2260 x 1325 PDF 0-160 y off limit x 460 last off limit
            click_around(
                hwnd,
                (0, max(0, RESOLUTION["x"] - 460)),
                (min(160, RESOLUTION_WITHOUT_TASKBAR["y"]), RESOLUTION_WITHOUT_TASKBAR["y"]),
            )
            matched = True
        elif any(value in text.value for value in ("Microsoft Word", "- Word")):
            # Word 1632 x 1092 Doc 0-300 y off limit
            click_around(
                hwnd,
                (0, RESOLUTION["x"]),
                (min(300, RESOLUTION_WITHOUT_TASKBAR["y"]), RESOLUTION_WITHOUT_TASKBAR["y"]),
            )
            matched = True
        elif any(value in text.value for value in ("Microsoft Excel", "- Excel")):
            # Excel 2624 x 1000 0-400 y off limit
            click_around(
                hwnd,
                (0, RESOLUTION["x"]),
                (min(400, RESOLUTION_WITHOUT_TASKBAR["y"]), RESOLUTION_WITHOUT_TASKBAR["y"]),
            )
            matched = True
        elif any(value in text.value for value in ("Microsoft PowerPoint", "- PowerPoint")):
            # Powerpoint 1300 x 974 0-300 y off limit 0-930 off limit
            click_around(
                hwnd,
                (min(300, RESOLUTION["x"]), RESOLUTION["x"]),
                (min(930, RESOLUTION_WITHOUT_TASKBAR["y"]), RESOLUTION_WITHOUT_TASKBAR["y"]),
            )
            matched = True
        if matched:
            KERNEL32.Sleep(20000)
            DOCUMENT_WINDOW_CLICK_AROUND = True
    return True


# Callback procedure invoked for every enumerated window.
def get_document_window(hwnd, lparam):
    global CLOSED_DOCUMENT_WINDOW
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        if any(
            value in text.value
            for value in (
                "- Microsoft",
                "- Word",
                "- Excel",
                "- PowerPoint",
                "- Adobe",
                "- Acrobat DC",
                "- Acrobat",
                "- Reader",
                "- PDF",
            )
        ):
            # send ALT+F4 equivalent
            log.info("Closing document window")
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None)
            CLOSED_DOCUMENT_WINDOW = True
    return True


def realistic_human_cursor_movement():
    random_dimension = random.randint(0, 1)  # Random binary choice for either x or y coordonate
    random_for_position_x = random.randint(
        2, 8
    )  # Dividing the screen in 2 to 8 for starting point (ignoring both extrimities as they are not needed)
    factor_x = random.choice([1 / random_for_position_x, random_for_position_x])
    random_for_position_y = random.randint(
        2, 8
    )  # Dividing the screen in 2 to 8 for starting point (ignoring both extrimities as they are not needed)
    factor_y = random.choice([1 / random_for_position_y, random_for_position_y])
    counter = 0
    start_x = RESOLUTION_WITHOUT_TASKBAR["x"] // factor_x
    start_y = RESOLUTION_WITHOUT_TASKBAR["y"] // factor_y
    start = datetime.now()
    while datetime.now() - start < timedelta(milliseconds=5000):
        fuzzy_x = random.randint(0, RESOLUTION_WITHOUT_TASKBAR["x"] // 128)
        fuzzy_y = random.randint(0, RESOLUTION_WITHOUT_TASKBAR["y"] // 128)
        if random_dimension == 0:
            counter += RESOLUTION_WITHOUT_TASKBAR["y"] // 64
            x = floor(start_x)
            y = floor(max(0, min(start_y + counter + fuzzy_y, RESOLUTION_WITHOUT_TASKBAR["y"])))
        else:
            counter += RESOLUTION_WITHOUT_TASKBAR["x"] // 64
            x = floor(max(0, min(start_x + counter + +fuzzy_x, RESOLUTION_WITHOUT_TASKBAR["x"])))
            y = floor(start_y)
        move_mouse_realistically(x, y)
        KERNEL32.Sleep(50)


def populate_clipboard():
    # add some random data to the clipboard
    randchars = list("   aaaabcddeeeeeefghhhiiillmnnnooooprrrsssttttuwy")
    cliplen = random.randint(10, 1000)
    clipval = [randchars[random.randint(0, len(randchars) - 1)] for _ in range(cliplen)]

    clipstr = "".join(clipval)
    cliprawstr = create_unicode_buffer(clipstr)
    if not USER32.OpenClipboard(None):
        return

    try:
        USER32.EmptyClipboard()
        buf = KERNEL32.GlobalAlloc(GMEM_MOVEABLE, sizeof(cliprawstr))
        if not buf:
            return

        lockbuf = KERNEL32.GlobalLock(buf)
        if not lockbuf:
            return

        memmove(lockbuf, cliprawstr, sizeof(cliprawstr))
        KERNEL32.GlobalUnlock(buf)
        USER32.SetClipboardData(CF_UNICODETEXT, buf)
    finally:
        USER32.CloseClipboard()


class Human(Auxiliary, Thread):
    """Human after all"""

    def __init__(self, options, config):
        global GIVEN_INSTRUCTIONS
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.enabled = self.config.human_windows
        self.do_run = self.enabled
        instruction_arg = self.options.get("human_instructions", "")
        if instruction_arg:
            GIVEN_INSTRUCTIONS = instruction_arg.split(" ")
            log.debug(GIVEN_INSTRUCTIONS)

    def stop(self):
        self.do_run = False

    def run(self):
        global DOCUMENT_WINDOW_CLICK_AROUND
        global GIVEN_INSTRUCTIONS
        global UIA_CLIENT
        uia_client = None
        try:
            randoff = random.randint(0, 10)

            populate_clipboard()

            nohuman = self.options.get("nohuman")
            if nohuman:
                return True

            refresh_mui_button_strings()

            nouia = str(self.options.get("nouia", "")).strip().lower() in ("1", "true", "yes", "on")
            if not nouia:
                uia_client = UIAClient()
                if not uia_client.initialize():
                    uia_client.close()
                    uia_client = None
            UIA_CLIENT = uia_client

            doc = False
            if hasattr(self.config, "file_type"):
                file_type = self.config.file_type
                file_name = self.config.file_name
                if (
                    "Rich Text Format" in file_type
                    or "Microsoft Word" in file_type
                    or "Microsoft Office Word" in file_type
                    or "MIME entity" in file_type
                    or file_name.endswith((".doc", ".docx", ".rtf", ".mht", ".mso"))
                ):
                    doc = True
                elif (
                    "Microsoft Office Excel" in file_type
                    or "Microsoft Excel" in file_type
                    or file_name.endswith((".xls", ".xlsx", ".xlsm", ".xlsb"))
                ):
                    doc = True
                elif "Microsoft PowerPoint" in file_type or file_name.endswith(
                    (".ppt", ".pptx", ".pps", ".ppsx", ".pptm", ".potm", ".potx", ".ppsm")
                ):
                    doc = True
                elif "PDF" in file_type or file_name.endswith(".pdf"):
                    doc = True

            USER32.EnumWindows(EnumWindowsProc(get_window_list), 0)
            interval = 300  # Interval of 300 was chosen it looked like human speed
            try:
                iter(GIVEN_INSTRUCTIONS)
            except TypeError:
                pass
            else:
                for instruction in GIVEN_INSTRUCTIONS:
                    log.info("Instruction: %s", instruction)
                    try:
                        if instruction.lower() == CLICK_CMD:
                            click_mouse()
                            continue
                        elif instruction.lower() == STOP_CMD:
                            return
                        match = re.match(CURSOR_POSITION_REGEX, instruction, flags=re.IGNORECASE)
                        if match and len(match.regs) == 3:
                            move_mouse_realistically(int(match.group(1)), int(match.group(2)))
                            KERNEL32.Sleep(interval)
                            continue
                        match = re.match(WAIT_REGEX, instruction, flags=re.IGNORECASE)
                        if match and len(match.regs) == 2:
                            KERNEL32.Sleep(int(match.group(1)))
                        match = re.match(INTERVAL_REGEX, instruction, flags=re.IGNORECASE)
                        if match and len(match.regs) == 2:
                            interval = int(match.group(1))
                    except Exception as e:
                        log.error("One of the instruction given is invalid: %s with error %s", instruction, str(e))
                        continue

            # These schedules used to be driven by a counter incremented once
            # per iteration and treated as seconds. The body is not
            # instantaneous - realistic_human_cursor_movement() alone runs for
            # 5 seconds and move_mouse_realistically() sleeps per step - so the
            # counter ran arbitrarily far behind the wall clock and every
            # interval keyed on it stretched with the sample's behaviour.
            # Deadlines keep the intervals the code intends: the first document
            # pass at 60s and every 30s after it, a foreground window switch on
            # the first iteration and every 15 + randoff seconds after that.
            now = time.monotonic()
            next_document_check = now + 60
            next_window_switch = now

            while self.do_run:
                now = time.monotonic()

                if doc and now >= next_document_check and not DOCUMENT_WINDOW_CLICK_AROUND and not CLOSED_DOCUMENT_WINDOW:
                    next_document_check = now + 30
                    USER32.EnumWindows(EnumWindowsProc(get_document_window_click_around), 0)
                    USER32.EnumWindows(EnumWindowsProc(get_document_window), 0)

                # only move the mouse 75% of the time, as malware can choose to act on an "idle" system just as it can on an "active" system
                rng = random.randint(0, 7)
                if rng > 1:  # 0-1
                    if rng < 4:  # 2-3 25% of the time move the cursor on the middle of the screen for x and move around
                        move_mouse_realistically(RESOLUTION["x"] // 2, 0)
                        # Avoid clicking on console windows and suspending execution
                        if not cursor_over_console_window():
                            click_mouse()
                        move_mouse_random()
                    elif (
                        rng >= 6
                    ):  # 6-7 25% of the time do realistic human movements for things like https://thehackernews.com/2023/11/lummac2-malware-deploys-new.html
                        realistic_human_cursor_movement()
                    else:  # 4-5 25% of the time move the cursor somewhere random and click/move around
                        x, y = get_random_click_coords(doc)
                        move_mouse_realistically(x, y)
                        # Avoid clicking on console windows and suspending execution
                        if not cursor_over_console_window():
                            click_mouse()
                        move_mouse_random()

                if time.monotonic() >= next_window_switch:
                    next_window_switch = time.monotonic() + 15 + randoff
                    # curwind = USER32.GetForegroundWindow()
                    other_hwnds = INITIAL_HWNDS.copy()
                    with contextlib.suppress(Exception):
                        other_hwnds.remove(USER32.GetForegroundWindow())
                    if len(other_hwnds):
                        USER32.SetForegroundWindow(other_hwnds[random.randint(0, len(other_hwnds) - 1)])

                USER32.EnumWindows(EnumWindowsProc(handle_window_interaction), 0)
                KERNEL32.Sleep(1000)
        except Exception:
            error_exc = traceback.format_exc()
            log.exception(error_exc)
        finally:
            UIA_CLIENT = None
            if uia_client is not None:
                uia_client.close()
