# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import math

log = logging.getLogger(__name__)

try:
    log.debug("Importing 'PIL.ImageChops'")
    # from PIL import ImageChops
    from PIL.ImageChops import difference

    log.debug("Importing 'PIL.ImageGrab'")
    from PIL import ImageGrab

    log.debug("Importing 'PIL.ImageDraw'")
    from PIL import ImageDraw

    try:
        from PIL import __version__
    except ImportError:
        from PIL import PILLOW_VERSION as __version__
    HAVE_PIL = True
    if int(__version__[0]) < 5:
        log.info("Please upgrade Pillow to >= 5.4.1 for best performance")

except Exception as e:
    HAVE_PIL = False
    log.error(e)


class Screenshot:
    """Get screenshots."""

    def _draw_rectangle(self, img, xy):
        """Draw a black rectangle.
        @param img: PIL Image object
        @param xy: Coordinates as refined in PIL rectangle() doc
        @return: Image with black rectangle
        """
        dr = ImageDraw.Draw(img)
        dr.rectangle(xy, fill="black", outline="black")
        return img

    def have_pil(self):
        """Is Python Image Library installed?
        @return: installed status.
        """
        return HAVE_PIL

    def equal(self, img1, img2, skip_area=None):
        """Compares two screenshots using Root-Mean-Square Difference (RMS).
        @param img1: screenshot to compare.
        @param img2: screenshot to compare.
        @return: equal status.
        """
        if not HAVE_PIL:
            return None

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

    def take(self):
        """Take a screenshot.
        @return: screenshot or None.
        """
        return ImageGrab.grab() if HAVE_PIL else None
