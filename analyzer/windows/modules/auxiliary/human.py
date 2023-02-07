#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import random
import traceback
from ctypes import POINTER, WINFUNCTYPE, c_bool, c_int, create_unicode_buffer, memmove, sizeof
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import BM_CLICK, CF_TEXT, GMEM_MOVEABLE, KERNEL32, USER32, WM_CLOSE, WM_GETTEXT, WM_GETTEXTLENGTH

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))
EnumChildProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))

SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_CXFULLSCREEN = 16
SM_CYFULLSCREEN = 17
RESOLUTION = {"x": USER32.GetSystemMetrics(SM_CXSCREEN), "y": USER32.GetSystemMetrics(SM_CYSCREEN)}
RESOLUTION_WITHOUT_TASKBAR = {"x": USER32.GetSystemMetrics(SM_CXFULLSCREEN), "y": USER32.GetSystemMetrics(SM_CYFULLSCREEN)}

INITIAL_HWNDS = []

CLOSED_OFFICE = False
OFFICE_CLICK_AROUND = False


def foreach_child(hwnd, lparam):
    classname = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname, 128)

    # Check if the class of the child is button.
    if (
        "button" in classname.value.lower()
        or "button" not in classname.value.lower()
        and classname.value in ("NUIDialog", "bosa_sdm_msword")
    ):
        # Get the text of the button.
        length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        if not length:
            return True
        text = create_unicode_buffer(length + 1)
        USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)
        textval = text.value.replace("&", "")
        if "Microsoft" in textval and classname.value in ("NUIDialog", "bosa_sdm_msword"):
            log.info("Issuing keypress on Office dialog")
            USER32.SetForegroundWindow(hwnd)
            # enter key down/up
            USER32.keybd_event(0x0D, 0x1C, 0, 0)
            USER32.keybd_event(0x0D, 0x1C, 2, 0)
            return False

        # we don't want to bother clicking any non-visible child elements, as they
        # generally won't respond and will cause us to fixate on them for the
        # rest of the analysis, preventing progress with visible elements

        if not USER32.IsWindowVisible(hwnd):
            return True

        # List of buttons labels to click.
        buttons = (
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
            "unzip",
            "open",
            "close the program",
            "save",
            "later",
            "finish",
            "end",
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
        )

        # List of buttons labels to not click.
        dontclick = (
            # english
            "check online for a solution",
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
        )

        # Check if the button is set as "clickable" and click it.
        for button in buttons:
            if button in textval.lower():
                dontclickb = False
                for btn in dontclick:
                    if btn in textval.lower():
                        dontclickb = True
                if not dontclickb:
                    log.info('Found button "%s", clicking it' % text.value)
                    USER32.SetForegroundWindow(hwnd)
                    KERNEL32.Sleep(1000)
                    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)
                    # only stop searching when we click a button
                    return False
    return True


# Callback procedure invoked for every enumerated window.
def foreach_window(hwnd, lparam):
    # If the window is visible, enumerate its child objects, looking
    # for buttons.
    if USER32.IsWindowVisible(hwnd):
        # we also want to inspect the "parent" windows, not just the children
        foreach_child(hwnd, lparam)
        USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)
    return True


def getwindowlist(hwnd, lparam):
    global INITIAL_HWNDS
    if USER32.IsWindowVisible(hwnd):
        INITIAL_HWNDS.append(hwnd)
    return True


def move_mouse():
    # To avoid mousing over desktop icons, use 1/4 of the total resolution as tgestarting pixel
    x = random.randint(RESOLUTION_WITHOUT_TASKBAR["x"] // 4, RESOLUTION_WITHOUT_TASKBAR["x"])
    y = random.randint(0, RESOLUTION_WITHOUT_TASKBAR["y"])

    # Originally was:
    # USER32.mouse_event(0x8000, x, y, 0, None)
    # Changed to SetCurorPos, since using GetCursorPos would not detect
    # the mouse events. This actually moves the cursor around which might
    # cause some unintended activity on the desktop. We might want to make
    # this featur optional.
    USER32.SetCursorPos(x, y)


def click_mouse():
    # Mouse down.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # Mouse up.
    USER32.mouse_event(4, 0, 0, 0, None)


def get_office_window_click_around(hwnd, lparm):
    global OFFICE_CLICK_AROUND
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        if any(value in text.value for value in ("Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint")):
            USER32.SetForegroundWindow(hwnd)
            # first click the middle
            USER32.SetCursorPos(RESOLUTION["x"] // 2, RESOLUTION["y"] // 2)
            click_mouse()
            KERNEL32.Sleep(50)
            click_mouse()
            KERNEL32.Sleep(500)
            # click through the middle with offset for cell position on side and scroll bar
            x = 80
            while x < RESOLUTION["x"] - 40:
                # make sure the window still exists
                if USER32.IsWindowVisible(hwnd):
                    USER32.SetForegroundWindow(hwnd)
                    USER32.SetCursorPos(x, RESOLUTION["y"] // 2)
                    click_mouse()
                    KERNEL32.Sleep(50)
                    click_mouse()
                    KERNEL32.Sleep(50)
                    if not USER32.IsWindowVisible(hwnd):
                        break
                    USER32.SetForegroundWindow(hwnd)
                    USER32.SetCursorPos(x, RESOLUTION["y"] // 2 + random.randint(80, 200))
                    click_mouse()
                    KERNEL32.Sleep(50)
                    click_mouse()
                    KERNEL32.Sleep(50)
                    if not USER32.IsWindowVisible(hwnd):
                        break
                    USER32.SetForegroundWindow(hwnd)
                    USER32.SetCursorPos(x, RESOLUTION["y"] // 2 - random.randint(80, 200))
                    click_mouse()
                    KERNEL32.Sleep(50)
                    click_mouse()
                    KERNEL32.Sleep(50)
                    x += random.randint(150, 200)
                    KERNEL32.Sleep(50)
                else:
                    log.info("Breaking out of office click loop as our window went away")
                    break
            KERNEL32.Sleep(20000)
            OFFICE_CLICK_AROUND = True
    return True


# Callback procedure invoked for every enumerated window.
def get_office_window(hwnd, lparam):
    global CLOSED_OFFICE
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        if any(value in text.value for value in ("- Microsoft", "- Word", "- Excel", "- PowerPoint")):
            # send ALT+F4 equivalent
            log.info("Closing Office window")
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None)
            CLOSED_OFFICE = True
    return True


class Human(Auxiliary, Thread):
    """Human after all"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.enabled = self.config.human_windows
        self.do_run = self.enabled

    def stop(self):
        self.do_run = False

    def run(self):
        global OFFICE_CLICK_AROUND
        try:
            seconds = 0
            randoff = random.randint(0, 10)

            # add some random data to the clipboard
            randchars = list("   aaaabcddeeeeeefghhhiiillmnnnooooprrrsssttttuwy")
            cliplen = random.randint(10, 1000)
            clipval = [randchars[random.randint(0, len(randchars) - 1)] for _ in range(cliplen)]

            clipstr = "".join(clipval)
            cliprawstr = create_unicode_buffer(clipstr)
            USER32.OpenClipboard(None)
            USER32.EmptyClipboard()

            buf = KERNEL32.GlobalAlloc(GMEM_MOVEABLE, sizeof(cliprawstr))
            lockbuf = KERNEL32.GlobalLock(buf)
            memmove(lockbuf, cliprawstr, sizeof(cliprawstr))
            KERNEL32.GlobalUnlock(buf)
            USER32.SetClipboardData(CF_TEXT, buf)
            USER32.CloseClipboard()

            nohuman = self.options.get("nohuman")
            if nohuman:
                return True

            officedoc = False
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
                    officedoc = True
                elif (
                    "Microsoft Office Excel" in file_type
                    or "Microsoft Excel" in file_type
                    or file_name.endswith((".xls", ".xlsx", ".xlsm", ".xlsb"))
                ):
                    officedoc = True
                elif "Microsoft PowerPoint" in file_type or file_name.endswith(
                    (".ppt", ".pptx", ".pps", ".ppsx", ".pptm", ".potm", ".potx", ".ppsm")
                ):
                    officedoc = True

            USER32.EnumWindows(EnumWindowsProc(getwindowlist), 0)

            while self.do_run:
                if officedoc and seconds > 45 and (seconds % 30) == 0 and not OFFICE_CLICK_AROUND and not CLOSED_OFFICE:
                    USER32.EnumWindows(EnumWindowsProc(get_office_window_click_around), 0)
                    USER32.EnumWindows(EnumWindowsProc(get_office_window), 0)

                # only move the mouse 75% of the time, as malware can choose to act on an "idle" system just as it can on an "active" system
                if random.randint(0, 7) > 1:
                    USER32.SetCursorPos(RESOLUTION["x"] // 2, 0)
                    click_mouse()
                    move_mouse()

                if (seconds % (15 + randoff)) == 0:
                    # curwind = USER32.GetForegroundWindow()
                    other_hwnds = INITIAL_HWNDS.copy()
                    with contextlib.suppress(Exception):
                        other_hwnds.remove(USER32.GetForegroundWindow())
                    if len(other_hwnds):
                        USER32.SetForegroundWindow(other_hwnds[random.randint(0, len(other_hwnds) - 1)])

                USER32.EnumWindows(EnumWindowsProc(foreach_window), 0)
                KERNEL32.Sleep(1000)
                seconds += 1
        except Exception:
            error_exc = traceback.format_exc()
            log.exception(error_exc)
