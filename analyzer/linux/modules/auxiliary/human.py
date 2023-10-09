# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import random
import time
from threading import Thread

try:
    import pyautogui
    from Xlib.display import Display

    HAVE_GUI_LIBS = True
except Exception:
    HAVE_GUI_LIBS = False

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

if HAVE_GUI_LIBS:
    RESOLUTION = {"x": pyautogui.size()[0], "y": pyautogui.size()[1]}

    DELAY = 0.5
    pyautogui.PAUSE = 1


def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])

    pyautogui.moveTo(x, y, duration=0.25)


def click_mouse():
    x = random.randint(100, RESOLUTION["x"])
    y = random.randint(100, RESOLUTION["y"])

    # pyautogui.click(x, y)
    pyautogui.mouseDown(x, y)
    pyautogui.mouseUp(x, y)


def destroyOfficeWindows(window):
    try:
        children = window.query_tree().children
    except Exception:
        return
    for w in children:
        if w.get_wm_class() in (
            ("libreoffice", "libreoffice-writer"),
            # ('soffice.bin', 'soffice.bin'),
            ("libreoffice", "libreoffice-calc"),
            ("libreoffice", "libreoffice-draw"),
            ("libreoffice", "libreoffice-impress"),
            ("win", "Xpdf"),
        ):
            log.debug("Destroying: %s", w.get_wm_class()[1])
            w.destroy()
        destroyOfficeWindows(w)


class Human(Thread, Auxiliary):
    """Simulate human."""

    def start(self):
        self.do_run = False

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.config = config
        self.enabled = self.config.human_linux
        self.do_run = self.enabled and HAVE_GUI_LIBS

        Thread.__init__(self)
        self.initComplete = False
        self.thread = Thread(target=self.run)
        self.thread.start()
        while not self.initComplete:
            self.thread.join(0.5)

        log.debug("Human init complete")

    def stop(self):
        if not self.enabled:
            return False

        self.do_run = False
        self.thread.join()

    def run(self):
        """Run Human.
        @return: operation status.
        """
        if not self.enabled:
            self.initComplete = True
            return False

        seconds = 0
        # Global disable flag.
        if "human" in self.options:
            self.do_move_mouse = int(self.options["human"])
            self.do_click_mouse = int(self.options["human"])
            self.do_click_buttons = int(self.options["human"])
        else:
            self.do_move_mouse = True
            self.do_click_mouse = True
            self.do_click_buttons = True

        # Per-feature enable or disable flag.
        if "human.move_mouse" in self.options:
            self.do_move_mouse = int(self.options["human.move_mouse"])

        if "human.click_mouse" in self.options:
            self.do_click_mouse = int(self.options["human.click_mouse"])

        if "human.click_buttons" in self.options:
            self.do_click_buttons = int(self.options["human.click_buttons"])

        self.initComplete = True

        while self.do_run:
            if seconds and not seconds % 60:
                display = Display()
                root = display.screen().root
                destroyOfficeWindows(root)

            if self.do_click_mouse:
                click_mouse()

            if self.do_move_mouse:
                move_mouse()

            # todo click buttons
            # if self.do_click_buttons:
            # foreach_window

            time.sleep(DELAY)
            seconds += 1

        return True
