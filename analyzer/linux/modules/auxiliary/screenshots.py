# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import asyncio
import logging
import threading
from threading import Thread

from lib.api.screenshot import HAVE_DBUS_NEXT, HAVE_PIL

if HAVE_PIL and HAVE_DBUS_NEXT:
    from PIL import Image
    from lib.api.screenshot import Screenshot, ScreenshotGrabber, ScreenshotsUnsupported

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

SHOT_DELAY = 1
# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None


class Screenshots(Thread, Auxiliary):
    """Take screenshots."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.screenshots_linux
        self.event = threading.Event()
        Thread.__init__(self)

    def stop(self):
        if not self.enabled:
            return False

        self.event.set()

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        if not self.enabled:
            return False

        if not HAVE_PIL:
            log.warning("Python Image Library is not installed, screenshots are disabled")
            return False

        if not HAVE_DBUS_NEXT:
            log.warning("dbus_next is not installed, screenshots are disabled")
            return False

        return asyncio.run(self.take_screenshots())

    async def take_screenshots(self):
        img_counter = 0
        img_last = None

        try:
            async with ScreenshotGrabber() as grabber:
                while not self.event.is_set():
                    await asyncio.sleep(SHOT_DELAY)

                    try:
                        img_path = await grabber.take_screenshot()
                    except Exception as e:
                        log.error("Cannot take screenshot: %s", e)
                        continue

                    if not img_path:
                        continue

                    # Technically, we shouldn't be using this blocking call
                    # (`close` or `upload_to_host`` either) in an asyncio
                    # event loop, but since this function is the only task we're running,
                    # we should be ok.
                    img_current = Image.open(img_path)

                    if img_last and Screenshot.equal(img_last, img_current, SKIP_AREA):
                        continue

                    img_counter += 1
                    upload_to_host(img_path, f"shots/{img_counter:0>4}.png")
                    if img_last:
                        img_last.close()
                    img_last = img_current
        except ScreenshotsUnsupported as err:
            log.error(str(err))
            return False

        return True
