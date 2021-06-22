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

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")
        try:
            path = os.path.join(self.reports_path, "report.json")
            with open(path, "wb") as report:
                if HAVE_ORJSON:
                    report.write(orjson.dumps(results, option=orjson.OPT_INDENT_2)) # orjson.OPT_SORT_KEYS |
                else:
                    report.write(json.dumps(results, indent=int(indent), ensure_ascii=False, encoding=encoding))
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
