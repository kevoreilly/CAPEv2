from __future__ import absolute_import

import codecs
import os

import simplejson as json

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


class LiteReport(Report):
    """A lite report with only specific parts"""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        encoding = self.options.get("encoding", "utf-8")

        keys_to_copy = (
            "CAPE",
            "procdump",
            "info",
            "signatures",
            "dropped",
            "static",
            "target",
            "network"
        )

        # lite report report only has the specific keys
        lite_report = {k: results[k] for k in results.keys() & keys_to_copy}

        # add specific keys from behavior
        behavior_keys_to_copy = (
            "processtree",
            "summary"
        )
        behavior = {k: results["behavior"][k] for k in results["behavior"].keys() & behavior_keys_to_copy}
        lite_report["behavior"] = behavior

        try:
            os.makedirs(f"{self.analysis_path}/lite/", exist_ok=True)
            path = os.path.join(self.analysis_path, "lite", "lite-report.json")

            with codecs.open(path, "w", "utf-8") as report:
                json.dump(lite_report,
                          report,
                          sort_keys=False,
                          separators=(',', ':'),
                          encoding='latin-1',
                          ensure_ascii=False)

        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
