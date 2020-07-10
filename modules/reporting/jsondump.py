# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import simplejson as json
import codecs

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
        ram_boost = self.options.get("ram_boost", True)

        try:
            path = os.path.join(self.reports_path, "report.json")
            with codecs.open(path, "w", "utf-8") as report:
                if ram_boost:
                    buf = json.dumps(results, sort_keys=False, indent=int(indent), encoding=encoding, ensure_ascii=False)
                    report.write(buf)
                else:
                    json.dump(results, report, sort_keys=False, indent=int(indent), encoding=encoding, ensure_ascii=False)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)
