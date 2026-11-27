# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import glob
import os
import zipfile

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.path_utils import path_delete, path_exists


class Decompression(Processing):
    """Decompresses analysis artifacts that have been compressed by the compression reporting module so re-analysis can be performed"""

    order = 0

    def _safe_extract_zip(self, zf: zipfile.ZipFile, dest_dir: str):
        dest_abs = os.path.abspath(dest_dir)
        for member in zf.infolist():
            target_path = os.path.abspath(os.path.join(dest_abs, member.filename))
            if not target_path.startswith(dest_abs + os.sep) and target_path != dest_abs:
                continue
            zf.extract(member, path=dest_abs)

    def run(self):
        self.key = "decompression"

        if path_exists(f"{self.memory_path}.zip"):
            try:
                with zipfile.ZipFile(f"{self.memory_path}.zip", "r") as thezip:
                    self._safe_extract_zip(thezip, self.analysis_path)
                path_delete(f"{self.memory_path}.zip")
            except Exception as e:
                raise CuckooProcessingError(f"Error extracting ZIP: {e}") from e

        for fzip in glob.glob(os.path.join(self.pmemory_path, "*.zip")):
            try:
                with zipfile.ZipFile(fzip, "r") as thezip:
                    self._safe_extract_zip(thezip, self.pmemory_path)
                path_delete(fzip)
            except Exception as e:
                raise CuckooProcessingError(f"Error extracting ZIP: {e}") from e

        return []
