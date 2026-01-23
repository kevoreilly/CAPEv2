# Copyright (C) 2024 dsecuma
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# This module uses some of the functions of the Windows auxiliary module
# for comparing screenshots.

import logging
import math
import os
import time
from io import BytesIO
from threading import Thread

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT

cfg = Config("auxiliary").get("QemuScreenshots")

log = logging.getLogger(__name__)

try:
    log.debug("Importing 'PIL.ImageChops.difference'")
    from PIL.ImageChops import difference

    log.debug("Importing 'PIL.ImageDraw'")
    from PIL import ImageDraw

    log.debug("Importing 'PIL.Image'")
    from PIL import Image

    HAVE_PIL = True

except Exception as e:
    HAVE_PIL = False
    log.error(e)

try:
    import libvirt

    HAVE_LIBVIRT = True
except ImportError:
    HAVE_LIBVIRT = False
    # log.error(e)


SHOT_DELAY = 1
# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None


class QEMUScreenshots(Auxiliary):
    """QEMU screenshots module."""

    def __init__(self):
        Auxiliary.__init__(self)
        Thread.__init__(self)
        log.info("QEMU screenshots module loaded")
        self.screenshot_thread = None
        self.enabled = cfg.get("enabled")
        self.do_run = self.enabled

    def start(self):
        """Start capture in a separate thread."""
        self.screenshot_thread = ScreenshotThread(self.task, self.machine, self.do_run)
        self.screenshot_thread.start()
        return True

    def stop(self):
        """Stop screenshot capture."""
        if self.screenshot_thread:
            self.screenshot_thread.stop()


class ScreenshotThread(Thread):
    """Thread responsible for taking screenshots."""

    def __init__(self, task, machine, do_run):
        Thread.__init__(self)
        self.task = task
        self.machine = machine
        self.do_run = do_run

        self.screenshots_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "shots")
        os.makedirs(self.screenshots_path, exist_ok=True)

    def stop(self):
        self.do_run = False

    def run(self):
        """Core screenshotting loop with image comparison."""
        img_counter = 0
        img_last = None

        while self.do_run:
            time.sleep(SHOT_DELAY)
            try:
                img_current = self._take_screenshot()
                if img_last and self._equal(img_last, img_current, SKIP_AREA):
                    continue

                img_last = img_current
                file_path = os.path.join(self.screenshots_path, f"{img_counter}.png")
                img_current.save(file_path, format="PNG")
                # log.info(f'Screenshot saved to {file_path}')
                img_counter += 1
            except (IOError, libvirt.libvirtError) as e:
                log.error("Cannot take screenshot: %s", str(e))
                continue

    def _take_screenshot(self):
        """Take screenshot from QEMU and return the PIL Image object."""
        conn = libvirt.open("qemu:///system")
        try:
            dom = conn.lookupByName(self.machine.label)
            stream = conn.newStream()
            dom.screenshot(stream, 0)  # 0 for primary display

            image_data = b""
            while True:
                chunk = stream.recv(262120)
                if not chunk:
                    break
                image_data += chunk

            return Image.open(BytesIO(image_data))
        finally:
            if stream:
                stream.finish()
            if conn:
                conn.close()

    def _draw_rectangle(self, img, xy):
        """Draw a black rectangle.
        @param img: PIL Image object
        @param xy: Coordinates as refined in PIL rectangle() doc
        @return: Image with black rectangle
        """
        dr = ImageDraw.Draw(img)
        dr.rectangle(xy, fill="black", outline="black")
        return img

    def _equal(self, img1, img2, skip_area=None):
        """Compares two screenshots using Root-Mean-Square Difference (RMS).
        @param img1: screenshot to compare.
        @param img2: screenshot to compare.
        @return: equal status.
        """

        # Trick to avoid getting a lot of screen shots only because the time in the windows
        # clock is changed.
        # We draw a black rectangle on the coordinates where the clock is locates, and then
        # run the comparison.
        # NOTE: the coordinates are changing with VM screen resolution.
        if skip_area:
            # Copying objects to draw in another object.
            img1 = img1.copy()
            img2 = img2.copy()
            # Draw a rectangle to cover windows clock.
            for img in (img1, img2):
                self._draw_rectangle(img, skip_area)

        # To get a measure of how similar two images are, we use
        # root-mean-square (RMS). If the images are exactly identical,
        # this value is zero.
        # diff = ImageChops.difference(img1, img2)
        diff = difference(img1, img2)
        h = diff.histogram()
        sq = (value * ((idx % 256) ** 2) for idx, value in enumerate(h))
        sum_of_squares = sum(sq)
        rms = math.sqrt(sum_of_squares / float(img1.size[0] * img1.size[1]))

        # Might need to tweak the threshold.
        return rms < 8
