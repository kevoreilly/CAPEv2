#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import random
import re
import traceback
from ctypes import POINTER, WINFUNCTYPE, byref, c_bool, c_int, create_unicode_buffer, memmove, sizeof, wintypes
from datetime import datetime, timedelta
from math import floor
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import BM_CLICK, CF_TEXT, GMEM_MOVEABLE, KERNEL32, USER32, WM_CLOSE, WM_GETTEXT, WM_GETTEXTLENGTH

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))
EnumChildProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))


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


def queryMousePosition():
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    return {"x": pt.x, "y": pt.y}


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
            # ru
            "установить",
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
            # ru
            "приoстановить",
            "отмена",
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
    # To avoid mousing over desktop icons, use 1/4 of the total resolution as the starting pixel
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


def click_around(hwnd, workable_range_x, workable_range_y):
    USER32.SetForegroundWindow(hwnd)
    # first click the middle
    USER32.SetCursorPos(RESOLUTION["x"] // 2, RESOLUTION["y"] // 2)
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
                USER32.SetCursorPos(x, RESOLUTION["y"] // 2)
                click_mouse()
                KERNEL32.Sleep(50)
                click_mouse()
                KERNEL32.Sleep(50)
                if not USER32.IsWindowVisible(hwnd):
                    break
                USER32.SetForegroundWindow(hwnd)
                USER32.SetCursorPos(x, random.randint(workable_range_y[0], workable_range_y[1]))
                click_mouse()
                KERNEL32.Sleep(50)
                click_mouse()
                KERNEL32.Sleep(50)
                if not USER32.IsWindowVisible(hwnd):
                    break
                USER32.SetForegroundWindow(hwnd)
                USER32.SetCursorPos(x, random.randint(workable_range_y[0], workable_range_y[1]))
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
                        USER32.SetCursorPos(int(point.group(1)), int(point.group(2)))
                KERNEL32.Sleep(50)
            else:
                log.info("Breaking out of document window click loop as our window went away")
                break


def get_document_window_click_around(hwnd, lparm):
    # (0,0) left upper corner
    global DOCUMENT_WINDOW_CLICK_AROUND
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
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
            click_around(hwnd, (0, RESOLUTION["X"] - 460), (160, RESOLUTION_WITHOUT_TASKBAR["Y"]))
        elif any(value in text.value for value in ("Microsoft Word",)):
            # Word 1632 x 1092 Doc 0-300 y off limit
            click_around(hwnd, (0, RESOLUTION["X"]), (300, RESOLUTION_WITHOUT_TASKBAR["Y"]))
        elif any(value in text.value for value in ("Microsoft Excel",)):
            # Excel 2624 x 1000 0-400 y off limit
            click_around(hwnd, (0, RESOLUTION["X"]), (400, RESOLUTION_WITHOUT_TASKBAR["Y"]))
        elif any(value in text.value for value in ("Microsoft PowerPoint",)):
            # Powerpoint 1300 x 974 0-300 y off limit 0-930 off limit
            click_around(hwnd, (300, RESOLUTION["X"]), (930, RESOLUTION_WITHOUT_TASKBAR["Y"]))
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
        USER32.SetCursorPos(x, y)
        KERNEL32.Sleep(50)


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

            USER32.EnumWindows(EnumWindowsProc(getwindowlist), 0)
            interval = 300  # Interval of 300 was chosen it looked like human speed
            try:
                iter(GIVEN_INSTRUCTIONS)
            except TypeError:
                pass
            else:
                for instruction in GIVEN_INSTRUCTIONS:
                    log.info("Instruction: %s" % instruction)
                    try:
                        if instruction.lower() == CLICK_CMD:
                            click_mouse()
                            continue
                        elif instruction.lower() == STOP_CMD:
                            return
                        match = re.match(CURSOR_POSITION_REGEX, instruction, flags=re.IGNORECASE)
                        if match and len(match.regs) == 3:
                            USER32.SetCursorPos(int(match.group(1)), int(match.group(2)))
                            KERNEL32.Sleep(interval)
                            continue
                        match = re.match(WAIT_REGEX, instruction, flags=re.IGNORECASE)
                        if match and len(match.regs) == 2:
                            KERNEL32.Sleep(int(match.group(1)))
                        match = re.match(INTERVAL_REGEX, instruction, flags=re.IGNORECASE)
                        if match and len(match.regs) == 2:
                            interval = int(match.group(1))
                    except Exception as e:
                        log.error("One of the instruction given is invalid: %s with error %s" % (instruction, e))
                        continue

            while self.do_run:
                if doc and seconds > 45 and (seconds % 30) == 0 and not DOCUMENT_WINDOW_CLICK_AROUND and not CLOSED_DOCUMENT_WINDOW:
                    USER32.EnumWindows(EnumWindowsProc(get_document_window_click_around), 0)
                    USER32.EnumWindows(EnumWindowsProc(get_document_window), 0)

                # only move the mouse 75% of the time, as malware can choose to act on an "idle" system just as it can on an "active" system
                rng = random.randint(0, 7)
                if rng > 1:  # 0-1
                    if rng < 4:  # 2-3 25% of the time move the cursor on the middle of the screen for x and move around
                        USER32.SetCursorPos(RESOLUTION["x"] // 2, 0)
                        click_mouse()
                        move_mouse()
                    elif (
                        rng >= 6
                    ):  # 6-7 25% of the time do realistic human movements for things like https://thehackernews.com/2023/11/lummac2-malware-deploys-new.html
                        realistic_human_cursor_movement()
                    else:  # 4-5 25% of the time move the cursor somewhere random and click/move around
                        USER32.SetCursorPos(
                            int(RESOLUTION_WITHOUT_TASKBAR["x"] / random.uniform(1, 16)),
                            int(RESOLUTION_WITHOUT_TASKBAR["y"] / random.uniform(1, 16)),
                        )
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
