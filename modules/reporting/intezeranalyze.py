# This report generator is specific for intezer analyze
# we creates this be cause the jsondump report can sometimes be too big

from __future__ import absolute_import
import os
import simplejson as json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


class JsonDump(Report):
    """Saves analysis results in JSON format specifically for intezer analyze needs"""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        keys_to_copy = {
            "CAPE",
            "procdump",
            "info",
            "signatures",
            "dropped",
            "static",
            "target"
        }

        # Intezer report only has the specific keys 
        intezer_report = {k: results[k] for k in results.keys() & keys_to_copy}

        try:
            path = os.path.join(self.reports_path, "intezer-report.json")

            with codecs.open(path, "w", "utf-8") as report:
                json.dump(intezer_report, report, sort_keys=False,
                          encoding='utf-8', ensure_ascii=False)

        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
