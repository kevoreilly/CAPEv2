# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import glob
import os
import zipfile

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class Decompression(Processing):
    """Decompresses analysis artifacts that have been compressed by the compression reporting module so re-analysis can be performed"""

    order = 0

    def run(self):
        self.key = "decompression"

        if os.path.exists(f"{self.memory_path}.zip"):
            try:
                thezip = zipfile.ZipFile(f"{self.memory_path}.zip", "r")
                thezip.extractall(path=self.analysis_path)
                thezip.close()
                os.unlink(f"{self.memory_path}.zip")
            except Exception as e:
                raise CuckooProcessingError(f"Error extracting ZIP: {e}")

        for fzip in glob.glob(os.path.join(self.pmemory_path, "*.zip")):
            try:
                thezip = zipfile.ZipFile(fzip, "r")
                thezip.extractall(path=self.pmemory_path)
                thezip.close()
                os.unlink(fzip)
            except Exception as e:
                raise CuckooProcessingError(f"Error extracting ZIP: {e}")

        return []
