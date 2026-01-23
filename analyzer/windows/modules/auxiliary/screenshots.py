# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import time
from contextlib import suppress
from io import BytesIO
from threading import Thread

try:
    from PIL import Image
except ImportError:
    pass

from lib.api.screenshot import Screenshot
from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

HAVE_CV2 = False
with suppress(ImportError):
    import cv2
    import numpy as np

    HAVE_CV2 = True


log = logging.getLogger(__name__)

SHOT_DELAY = 1
# Skip the following area when comparing screen shots.
# Example for 800x600 screen resolution.
# SKIP_AREA = ((735, 575), (790, 595))
SKIP_AREA = None


def handle_qr_codes(image_data):
    """Extract URL from QR code if present."""
    if not HAVE_CV2:
        return None

    try:
        image = Image.open(image_data)
        # Convert PIL image to BGR numpy array for OpenCV
        img = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        extracted, _, _ = detector.detectAndDecode(img)
        # Simple URL detection
        if extracted and "://" in extracted[:10]:
            return extracted
    except Exception as e:
        log.debug("Error in handle_qr_codes: %s", e)

    return None


class Screenshots(Auxiliary, Thread):
    """Take screenshots."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.enabled = config.screenshots_windows
        self.screenshots_qr = getattr(config, "screenshots_qr", False)
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

                if self.screenshots_qr and HAVE_CV2:
                    url = handle_qr_codes(tmpio)
                    if url:
                        log.info("QR code detected with URL: %s", url)
                        try:
                            # os.startfile is Windows only and usually works for URLs
                            os.startfile(url)
                        except Exception as e:
                            log.error("Failed to open QR URL: %s", e)
                    tmpio.seek(0)

                nf = NetlogFile()
                nf.init(f"shots/{str(img_counter).rjust(4, '0')}.jpg")
                for chunk in tmpio:
                    nf.sock.send(chunk)
                nf.close()
                img_last = img_current

        return True
