# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    import json

    HAVE_ORJSON = False

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode()
        raise TypeError

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        try:
            path = os.path.join(self.reports_path, "report.json")
            if HAVE_ORJSON:
                with open(path, "wb") as report:
                    report.write(orjson.dumps(results, option=orjson.OPT_INDENT_2, default=self.default))  # orjson.OPT_SORT_KEYS |
            else:
                with open(path, "w") as report:
                    json.dump(results, report, sort_keys=False, indent=int(indent), ensure_ascii=False)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to generate JSON report: {e}")
