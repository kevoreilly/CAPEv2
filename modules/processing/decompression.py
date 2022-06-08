# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

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
                with zipfile.ZipFile(f"{self.memory_path}.zip", "r") as thezip:
                    thezip.extractall(path=self.analysis_path)
                os.unlink(f"{self.memory_path}.zip")
            except Exception as e:
                raise CuckooProcessingError(f"Error extracting ZIP: {e}") from e

        for fzip in glob.glob(os.path.join(self.pmemory_path, "*.zip")):
            try:
                with zipfile.ZipFile(fzip, "r") as thezip:
                    thezip.extractall(path=self.pmemory_path)
                os.unlink(fzip)
            except Exception as e:
                raise CuckooProcessingError(f"Error extracting ZIP: {e}") from e

        return []
