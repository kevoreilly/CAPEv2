# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import zipfile

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.path_utils import path_delete, path_exists


class Compression(Report):
    """Compresses analysis artifacts after processing/signatures are complete for permanent storage."""

    def run(self, results):
        zipmemdump = self.options.get("zipmemdump", False)
        zipprocdump = self.options.get("zipprocdump", False)
        zipmemstrings = self.options.get("zipmemstrings", False)
        zipprocstrings = self.options.get("zipprocstrings", False)

        for proc in results.get("procmemory", []) or []:
            dmp_path = proc.get("file")
            strings_path = proc.get("strings_path")

            for option in (zipprocdump, zipprocstrings):
                if option and dmp_path and dmp_path.endswith((".dmp", ".strings")) and path_exists(dmp_path):
                    try:
                        f = zipfile.ZipFile(f"{dmp_path}.zip", "w")
                        f.write(dmp_path, os.path.basename(dmp_path), zipfile.ZIP_DEFLATED)
                        f.close()
                        path_delete(dmp_path)
                        proc["file"] = f"{dmp_path}.zip"
                    except Exception as e:
                        raise CuckooReportError(f"Error creating Process Memory Zip File: {e}")

        if zipmemdump and self.memory_path and path_exists(self.memory_path):
            try:
                f = zipfile.ZipFile(f"{self.memory_path}.zip", "w", allowZip64=True)
                f.write(self.memory_path, os.path.basename(self.memory_path), zipfile.ZIP_DEFLATED)
                f.close()
                path_delete(self.memory_path)
            except Exception as e:
                raise CuckooReportError(f"Error creating Full Memory Zip File: {e}")

        if zipmemstrings and self.memory_path and path_exists(f"{self.memory_path}.strings"):
            strings_path = f"{self.memory_path}.strings"
            try:
                f = zipfile.ZipFile(f"{strings_path}.zip", "w", allowZip64=True)
                f.write(strings_path, os.path.basename(strings_path), zipfile.ZIP_DEFLATED)
                f.close()
                path_delete(strings_path)
                strings_path = f"{strings_path}.zip"
            except Exception as e:
                raise CuckooReportError(f"Error creating Full Memory Strings Zip File: {e}")
