# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.utils import create_zip
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.path_utils import path_write_file

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    import json

    HAVE_ORJSON = False

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    # ensure we run after the SubmitCAPE
    order = 10

    def default(self, obj):
        if isinstance(obj, bytes):
            try:
                result = obj.decode()
            except UnicodeDecodeError:
                result = f"UnicodeDecodeError, bytes hex str: {obj.hex()}"
            return result
        raise TypeError

    def _sanitize_surrogates(self, obj):
        if isinstance(obj, str):
            return obj.encode("utf-8", errors="replace").decode("utf-8")
        if isinstance(obj, dict):
            return {self._sanitize_surrogates(k): self._sanitize_surrogates(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._sanitize_surrogates(item) for item in obj]
        if isinstance(obj, tuple):
            return [self._sanitize_surrogates(item) for item in obj]
        return obj

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        try:
            path = os.path.join(self.reports_path, "report.json")
            if HAVE_ORJSON:
                try:
                    payload = orjson.dumps(results, option=orjson.OPT_INDENT_2, default=self.default)
                except TypeError:
                    payload = orjson.dumps(
                        self._sanitize_surrogates(results),
                        option=orjson.OPT_INDENT_2,
                        default=self.default,
                    )
                _ = path_write_file(path, payload)  # orjson.OPT_SORT_KEYS |
            else:
                with open(path, "w", encoding="utf-8", errors="replace") as report:
                    json.dump(results, report, sort_keys=False, indent=int(indent), ensure_ascii=False)

            # useful if you frequently fetch zipped reports to not compress in memory all the time
            if self.options.get("store_compressed") and os.path.exists(path):
                zip_path = path + ".zip"
                zipped_io = create_zip(path)
                with open(zip_path, "wb") as f:
                    f.write(zipped_io.getvalue())

        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to generate JSON report: {e}")
