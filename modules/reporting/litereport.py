# Copyright (C) 2021 Intezer
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

import chardet

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.path_utils import path_write_file

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    import json

    HAVE_ORJSON = False


class LiteReport(Report):
    """A lite report with only specific parts"""

    def default(self, obj):
        if isinstance(obj, bytes):
            encoding = chardet.detect(obj)["encoding"]
            if encoding:
                return obj.decode(encoding, errors="replace")
            else:
                return obj.decode("utf-8", errors="replace")
        raise TypeError

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        keys_to_copy = self.options.keys_to_copy.split(" ")

        # lite report report only has the specific keys
        lite_report = {k: results[k] for k in results.keys() & keys_to_copy}

        # add specific keys from behavior
        behavior_keys_to_copy = self.options.behavior_keys_to_copy.split(" ")
        behavior = {k: results["behavior"][k] for k in results["behavior"].keys() & behavior_keys_to_copy}
        lite_report["behavior"] = behavior

        path = os.path.join(self.reports_path, "lite.json")
        try:
            if HAVE_ORJSON:
                _ = path_write_file(
                    path, orjson.dumps(lite_report, option=orjson.OPT_INDENT_2, default=self.default)
                )  # orjson.OPT_SORT_KEYS |
            else:
                with open(path, "w") as report:
                    json.dump(lite_report, report, sort_keys=False, separators=(",", ":"), ensure_ascii=False)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to generate JSON report: {e}")
