from __future__ import absolute_import
import logging
import os
import shutil

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import get_memdump_path

log = logging.getLogger(__name__)
repconf = Config("reporting")


class TMPFSCLEAN(Report):
    "Remove/save memdump"
    order = 9998

    def run(self, results):
        action = "delete"
        src = get_memdump_path(results["info"]["id"])
        if "store_memdump" in results["info"]["options"]:
            action = "store"

        if repconf.tmpfsclean.key in results:
            if any(["checkme" in block for block in results[repconf.tmpfsclean.key]]):
                action = "store"

        if action == "delete":
            log.debug("Deleting memdump: %s", src)
            if os.path.exists(src):
                os.remove(src)
        else:
            dest = get_memdump_path(results["info"]["id"], analysis_folder=True)
            log.debug("Storing memdump: %s", dest)
            if src != dest:
                if os.path.exists(src):
                    shutil.move(src, dest)
                if os.path.exists(f"{src}.strings"):
                    shutil.move(f"{src}.strings", f"{dest}.strings")
