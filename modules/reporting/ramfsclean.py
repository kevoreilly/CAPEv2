from __future__ import absolute_import
import os
import shutil
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.utils import get_memdump_path

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")


class RAMFSCLEAN(Report):
    "Remove/save memdump"
    order = 9998

    def run(self, results):
        action = "delete"
        src = get_memdump_path(results["info"]["id"])
        if "store_memdump" in results["info"]["options"]:
            action  = "store"

        if reporting_conf.ramfsclean.key in results:
            if any(["checkme" in block for block in results[reporting_conf.ramfsclean.key]]):
                action = "store"

        if action == "delete":
            log.debug("Deleting memdump: {}".format(src))
            if os.path.exists(src):
                os.remove(src)
        else:
            dest = get_memdump_path(results["info"]["id"], analysis_folder=True)
            log.debug("Storing memdump: {}".format(dest))
            if os.path.exists(src):
                shutil.move(src, dest)
