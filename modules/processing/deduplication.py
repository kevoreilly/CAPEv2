# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import logging
import os
import re

HAVE_IMAGEHASH = False
try:
    import imagehash

    HAVE_IMAGEHASH = True
except ImportError:
    print("Missed dependency: poetry run pip install ImageHash")

try:
    from PIL import Image

    Image.logger.setLevel(logging.WARNING)
except ImportError:
    print("Missed dependency: poetry install")

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger()


def reindex_screenshots(shots_path):
    for i, cur_basename in enumerate(sorted(os.listdir(shots_path))):
        extension = os.path.splitext(cur_basename)[-1]
        new_basename = "%s%s" % (str(i).rjust(4, "0"), extension)
        log.debug("renaming %s to %s", cur_basename, new_basename)
        old_path = os.path.join(shots_path, cur_basename)
        new_path = os.path.join(shots_path, new_basename)
        os.rename(old_path, new_path)


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
        if not path_exists(shots_path) or not HAVE_IMAGEHASH:
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

        except Exception as e:
            log.error(e)

        return shots
