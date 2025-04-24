import logging
import shutil

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.path_utils import path_delete, path_exists
from lib.cuckoo.common.utils import get_memdump_path

log = logging.getLogger(__name__)


class TMPFSCLEAN(Report):
    "Remove/save memdump"

    order = 9998

    def run(self, results):
        action = "delete"
        src = get_memdump_path(results["info"]["id"])
        if "store_memdump" in results["info"]["options"]:
            action = "store"

        if self.options.key in results and any(["checkme" in block for block in results[self.options.key]]):
            action = "store"

        if action == "delete":
            log.debug("Deleting memdump: %s", src)
            if path_exists(src):
                path_delete(src)
            if path_exists(f"{src}.strings"):
                path_delete(f"{src}.strings")
        else:
            dest = get_memdump_path(results["info"]["id"], analysis_folder=True)
            log.debug("Storing memdump: %s", dest)
            if src != dest:
                if path_exists(src):
                    shutil.move(src, dest)
                if path_exists(f"{src}.strings"):
                    shutil.move(f"{src}.strings", f"{dest}.strings")
