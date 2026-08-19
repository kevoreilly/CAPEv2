# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import logging
import os
import re

log = logging.getLogger()

# Lazy-loaded imagehash bindings — defer C-extension import that spawns native
# threads at module load time. See PreforkEngine._assert_single_threaded.
# imagehash transitively loads PIL/Pillow C extensions which spawn ~15 kernel
# threads on import; deferring to first use keeps the prefork supervisor
# single-threaded so it can safely fork workers.
_IMAGEHASH_BINDINGS = None  # None = not probed; module = loaded; False = unavailable


def _load_imagehash():
    """Import imagehash on demand, cache the result. Returns the imagehash module or False."""
    global _IMAGEHASH_BINDINGS
    if _IMAGEHASH_BINDINGS is not None:
        return _IMAGEHASH_BINDINGS
    try:
        import imagehash as _imagehash

        _IMAGEHASH_BINDINGS = _imagehash
    except ImportError:
        log.error("Missed dependency: poetry run pip install ImageHash")
        _IMAGEHASH_BINDINGS = False
    return _IMAGEHASH_BINDINGS


HAVE_CV2 = False
try:
    import cv2

    HAVE_CV2 = True
except ImportError:
    print("Missed dependency: poetry run pip install opencv-python")

HAVE_ZXING = False
try:
    import zxingcpp

    HAVE_ZXING = True
except ImportError:
    pass

try:
    from PIL import Image

    Image.logger.setLevel(logging.WARNING)
except ImportError:
    log.error("Missed dependency: poetry install")

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists


def reindex_screenshots(shots_path):
    for i, cur_basename in enumerate(sorted(os.listdir(shots_path))):
        extension = os.path.splitext(cur_basename)[-1]
        new_basename = "%s%s" % (str(i).rjust(4, "0"), extension)
        log.debug("renaming %s to %s", cur_basename, new_basename)
        old_path = os.path.join(shots_path, cur_basename)
        new_path = os.path.join(shots_path, new_basename)
        os.rename(old_path, new_path)


def _qr_decode_zxing(image_path):
    """Decode QR codes using zxing-cpp. Supports multiple barcodes per image."""
    try:
        with Image.open(image_path) as img:
            results = zxingcpp.read_barcodes(img)
        urls = []
        for result in results:
            text = result.text
            if text and "://" in text[:10]:
                urls.append(text)
        return urls
    except Exception as e:
        log.error("zxing-cpp error on %s: %s", image_path, e)
        return []


def _qr_decode_cv2(image_path):
    """Decode QR codes using OpenCV. Single barcode per image."""
    try:
        img = cv2.imread(image_path)
        if img is None:
            return []
        detector = cv2.QRCodeDetector()
        extracted, points, straight_qrcode = detector.detectAndDecode(img)
        if extracted and "://" in extracted[:10]:
            return [extracted]
    except Exception as e:
        log.error("Error detecting QR in %s: %s", image_path, e)
    return []


def handle_qr_codes(image_path):
    if HAVE_ZXING:
        urls = _qr_decode_zxing(image_path)
        if urls:
            return urls[0]
        return None
    if HAVE_CV2:
        urls = _qr_decode_cv2(image_path)
        if urls:
            return urls[0]
    return None


def handle_qr_codes_all(image_path):
    """Return all QR code URLs found in an image."""
    if HAVE_ZXING:
        return _qr_decode_zxing(image_path)
    if HAVE_CV2:
        return _qr_decode_cv2(image_path)
    return []


class Deduplicate(Processing):
    """Deduplicate screenshots."""

    def deduplicate_images(self, userpath, hashfunc):
        """
        Remove duplicate images from a path
        :userpath: path of the image files
        :hashfunc: type of image hashing method
        """

        def is_image(filename):
            img_ext = (".jpg", ".png", ".gif", ".bmp", ".gif")
            return filename.lower().endswith(img_ext)

        """
        Available hashs functions:
            ahash:      Average hash
            phash:      Perceptual hash
            dhash:      Difference hash
            whash-haar: Haar wavelet hash
            whash-db4:  Daubechies wavelet hash
        """
        dd_img_set = []

        image_paths = [os.path.join(userpath, path) for path in os.listdir(userpath) if is_image(path)]
        images = collections.defaultdict(list)
        for img in sorted(image_paths):
            hash = hashfunc(Image.open(img))
            images[hash].append(img)
        for img_list in images.values():
            dd_img_set.append(os.path.basename(img_list[0]))

        image_filenames = {os.path.basename(x) for x in image_paths}
        duplicates = set(image_filenames) - set(dd_img_set)
        for dupe in duplicates:
            log.debug("removing duplicate screenshot: %s", dupe)
            os.remove(os.path.join(userpath, dupe))
        reindex_screenshots(userpath)

        # Found that we get slightly more complete images in most cases when getting rid of images with close bit distance.
        # We flip the list back around after prune.
        dd_img_set.sort(reverse=True)
        return dd_img_set

    def run(self):
        """Creates a new key in the report dict for
        the deuplicated screenshots.
        """
        self.key = "deduplicated_shots"
        shots = []

        shots_path = os.path.join(self.analysis_path, "shots")
        imagehash = _load_imagehash()
        if not path_exists(shots_path) or not imagehash:
            return shots

        hashmethod = self.options.get("hashmethod", "ahash")
        try:
            if hashmethod == "ahash":
                hashfunc = imagehash.average_hash
            elif hashmethod == "phash":
                hashfunc = imagehash.phash
            elif hashmethod == "dhash":
                hashfunc = imagehash.dhash
            elif hashmethod == "whash-haar":
                hashfunc = imagehash.whash
            elif hashmethod == "whash-db4":

                def hashfunc(img):
                    return imagehash.whash(img, mode="db4")

            else:
                # Default
                hashfunc = imagehash.average_hash

            shots_path = os.path.join(self.analysis_path, "shots")
            screenshots = sorted(self.deduplicate_images(userpath=shots_path, hashfunc=hashfunc))
            shots = [re.sub(r"\.(png|jpg)$", "", screenshot) for screenshot in screenshots]

            if HAVE_ZXING or HAVE_CV2:
                qr_urls = set()
                for img_name in os.listdir(shots_path):
                    if not img_name.lower().endswith((".jpg", ".png")):
                        continue
                    for url in handle_qr_codes_all(os.path.join(shots_path, img_name)):
                        qr_urls.add(url)

                if qr_urls:
                    self.results["qr_urls"] = list(qr_urls)

        except Exception as e:
            log.error(e)

        return shots
