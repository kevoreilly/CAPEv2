import json
import logging
import os.path
import subprocess

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger()


class FLOSS(Processing):
    """Extract strings from sample using FLOSS."""

    # TODO: Move floss into processing.conf for `enabled` and `on_demand`
    def run(self):
        """Run FLOSS to extract strings from sample.
        @return: dictionary parsed from the JSON FLOSS output.
        """
        self.key = "floss"
        results = {}

        # handle file targets
        if self.task["category"] in {"file", "static"}:
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError(f"Sample file doesn't exist: {self.file_path}")

            try:
                # ToDo stop using file and move to direct python integration
                output_json_path = os.path.join(self.analysis_path, "floss.json")
                floss_options = [
                    self.options.get("floss_path", "floss"),
                    "--output-json",
                    output_json_path,
                    self.file_path,
                ]

                # handle shellcode samples
                if self.task["package"] in {"Shellcode", "Shellcode_x64"}:
                    floss_options.insert(-1, "-s")

                subprocess.run(
                    floss_options,
                    check=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    encoding="utf8",
                    timeout=int(self.options.get("timeout", 120)),
                )

                with open(output_json_path) as output_fp:
                    results = json.load(output_fp)
            except subprocess.CalledProcessError as e:
                # TODO: improve error handling
                log.warning("FLOSS failed: %s", e)
                log.warning(e.stderr)

        return results
