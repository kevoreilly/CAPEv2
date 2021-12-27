# Copyright (C) 2021 Intezer
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    import json

    HAVE_ORJSON = False

repconf = Config("reporting")


class LiteReport(Report):
    """A lite report with only specific parts"""

    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode()
        raise TypeError

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        encoding = self.options.get("encoding", "utf-8")

        keys_to_copy = repconf.litereport.keys_to_copy.split(" ")

        # lite report report only has the specific keys
        lite_report = {k: results[k] for k in results.keys() & keys_to_copy}

        # add specific keys from behavior
        behavior_keys_to_copy = repconf.litereport.behavior_keys_to_copy.split(" ")
        behavior = {k: results["behavior"][k] for k in results["behavior"].keys() & behavior_keys_to_copy}
        lite_report["behavior"] = behavior

        path = os.path.join(self.reports_path, "lite.json")
        try:
            if HAVE_ORJSON:
                with open(path, "wb") as report:
                    report.write(
                        orjson.dumps(lite_report, option=orjson.OPT_INDENT_2, default=self.default)
                    )  # orjson.OPT_SORT_KEYS |
            else:
                with open(path, "w") as report:
                    json.dump(lite_report, report, sort_keys=False, separators=(",", ":"), ensure_ascii=False)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to generate JSON report: {e}")
