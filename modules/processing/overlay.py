import base64
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_write_file

log = logging.getLogger(__name__)


class process_overlay_file(object):
    """Returns the file information of the containing overlay data"""

    def __init__(self, overlay_fullpath):
        self.overlay_fullpath = overlay_fullpath

    def run(self):
        if not self.options.enabled:
            return {}

        if not path_exists(self.overlay_fullpath):
            return {}

        file_info, _ = File(file_path=self.overlay_fullpath).get_all()
        return file_info


class extract_overlay_data(Processing):
    """Makes use of static.py's result to determine if there is overlay data. Only works for PE for now.
    If overlay has been detected by static.py, we extract the whole data and save them in a file
    @returns: Up to first 4096 bytes of overlay data added as part of the json, full data will need to be downloaded
    """

    # To tell CAPE to run this after first round of processing is done
    order = 2

    def run(self):
        if "static" not in self.results:
            return None

        self.key = "static"  # uses the existing "static" sub container to add in the overlay data
        output = self.results["static"]

        if not output.get("pe", {}).get("overlay"):
            return output

        overlay_size = int(output["pe"]["overlay"]["size"], 16)

        # Extract out the overlay data
        try:
            with open(self.file_path, "rb") as f:
                f.seek(-overlay_size, os.SEEK_END)
                data = f.read()
            output["pe"]["overlay"]["data"] = base64.b64encode(data[: min(overlay_size, 4096)])

            fld = os.path.join(self.analysis_path, "files")
            if not path_exists(fld):
                log.warning("Folder not present, creating it. Might affect the displaying of (overlay) results on the web")
                path_mkdir(fld)

            fld = os.path.join(fld, "extracted_overlay")
            _ = path_write_file(fld, data)

            output["pe"]["overlay"]["fileinfo"] = process_overlay_file(fld).run()

        except Exception as e:
            log.error(e)

        return output
