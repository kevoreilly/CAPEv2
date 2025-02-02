# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import time
from io import BytesIO
from threading import Thread

from lib.api.screenshot import Screenshot
from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

# from tempfile import NamedTemporaryFile
# from contextlib import suppress
# HAVE_CV2 = False
# with suppress(ImportError):
#    import cv2
#    HAVE_CV2 = True


log = logging.getLogger(__name__)

SHOT_DELAY = 1
# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None

"""
def handle_qr_codes(image_data):
    # In most cases requires human interation.
    # Test file: 520eb94193ac451127d8595ff33fb562
    # https://app.any.run/tasks/ac0b6323-5476-4fed-9c8a-3b574742349c/
    # https://opencv.org/get-started/
    # Inside of windows: pip3 install opencv-python
    image = Image.open(image_data)
    with NamedTemporaryFile() as temp_file:
        image.save(temp_file.name)
        img = cv2.imread(temp_file.name)
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        detector = cv2.QRCodeDetector()
        extracted, _, _ = detector.detectAndDecode(img)
        # detect url?
        if extracted and "://" in extracted[:10]:
            return extracted
"""


class Screenshots(Auxiliary, Thread):
    """Take screenshots."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.enabled = config.screenshots_windows
        self.do_run = self.enabled

    def stop(self):
        """Stop screenshotting."""
        self.do_run = False

    def run(self):
        """Run screenshotting.
        @return: operation status.
        """
        if not Screenshot().have_pil():
            log.warning("Python Image Library is not installed, screenshots are disabled")
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

            if img_last and Screenshot().equal(img_last, img_current, SKIP_AREA):
                continue

            img_counter += 1
            # workaround as PIL can't write to the socket file object :(
            with BytesIO() as tmpio:
                img_current.save(tmpio, format="JPEG")
                tmpio.seek(0)
                # if HAVE_CV2: # ToDo on/off
                #   url = handle_qr_codes(tmpio)
                #   tmpio.seek(0)
                # ToDo open url in browser

                nf = NetlogFile()
                nf.init(f"shots/{str(img_counter).rjust(4, '0')}.jpg")
                for chunk in tmpio:
                    nf.sock.send(chunk)
                nf.close()
                img_last = img_current

        return True
