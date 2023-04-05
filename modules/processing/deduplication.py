# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import re

HAVE_IMAGEHASH = False
try:
    import imagehash

    HAVE_IMAGEHASH = True
except ImportError:
    print("Missed dependency: pip3 install ImageHash")

try:
    from PIL import Image

    Image.logger.setLevel(logging.WARNING)
except ImportError:
    print("Missed dependency: pip3 install Pillow")

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger()


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

        image_filenames = [os.path.join(userpath, path) for path in os.listdir(userpath) if is_image(path)]
        images = {}
        for img in sorted(image_filenames):
            hash = hashfunc(Image.open(img))
            images.setdefault(hash, []).append(img)
        for img_list in images.values():
            dd_img_set.append(os.path.basename(img_list[0]))
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

        if not HAVE_IMAGEHASH:
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
            if path_exists(shots_path):
                screenshots = sorted(self.deduplicate_images(userpath=shots_path, hashfunc=hashfunc))
                shots = [re.sub(r"\.(png|jpg)$", "", screenshot) for screenshot in screenshots]
        except Exception as e:
            log.error(e)

        return shots
