import glob
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_read_file

log = logging.getLogger()


class script_log_processing(Processing):
    """
    Output reads output of script from logs
    Adds to report.json to be viewed on the web
    """

    # To tell CAPE to run this after first round of processing is done
    order = 2

    def run(self):
        self.key = "debug"  # uses the existing "static" sub container to add in the overlay data
        output = self.results["debug"]

        # Extract out the overlay data

        for file_path in glob.glob(os.path.join(self.logs_path, "*script.log")):
            file_name = os.path.basename(file_path)
            try:
                log.info("Processing File: %s", file_path)
                file_data = path_read_file(file_path, mode="text")
                if file_name == "pre_script.log":
                    output["pre_script_log"] = file_data
                elif file_name == "during_script.log":
                    output["during_script_log"] = file_data

            except Exception as e:
                log.error(e)

        return output
