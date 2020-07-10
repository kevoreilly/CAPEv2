# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)

log.debug("Importing 'time'")
import time

log.debug("Importing 'StringIO'")
from io import BytesIO

log.debug("Importing 'Thread'")
from threading import Thread

log.debug("Importing 'Auxiliary'")
from lib.common.abstracts import Auxiliary

log.debug("Importing 'NetlogFile'")
from lib.common.results import NetlogFile

log.debug("Importing 'Screenshot'")
from lib.api.screenshot import Screenshot

log.debug("Imports OK")

SHOT_DELAY = 1
# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None


class Screenshots(Auxiliary, Thread):
    """Take screenshots."""

    def __init__(self, options={}, analyzer=None):
        Auxiliary.__init__(self, options={}, analyzer=None)
        Thread.__init__(self)
        self.do_run = True

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        if not Screenshot().have_pil():
            log.warning("Python Image Library is not installed, " "screenshots are disabled")
            return False

        img_counter = 0
        img_last = None

        while self.do_run:
            time.sleep(SHOT_DELAY)

            try:
                img_current = Screenshot().take()
            except IOError as e:
                log.error("Cannot take screenshot: %s", e)
                continue

            if img_last:
                if Screenshot().equal(img_last, img_current, SKIP_AREA):
                    continue

            img_counter += 1
            # workaround as PIL can't write to the socket file object :(
            tmpio = BytesIO()
            img_current.save(tmpio, format="JPEG")
            tmpio.seek(0)

            # now upload to host from the StringIO
            nf = NetlogFile()
            nf.init("shots/%s.jpg" % str(img_counter).rjust(4, "0"))
            for chunk in tmpio:
                nf.sock.send(chunk)
            nf.close()
            img_last = img_current

        return True
