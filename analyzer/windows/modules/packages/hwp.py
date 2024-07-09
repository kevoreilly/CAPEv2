# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class HWP(Package):
    """Hangul (Korean) Word Processor File 5.x analysis package."""

    PATHS = [("ProgramFiles", "Hnc", "Hwp80", "Hwp.exe"), ("ProgramFiles", "Hnc", "Office 2020", "HOffice110", "Bin", "Hword.exe")]
    summary = "Open a document with Hangul Word Processor"
    description = """Use 'Hnc\\Hwp80\\Hwp.exe <sample>' to open the sample.
    Alternatively, use 'Hnc\\Office 2020\\HOffice110\\Bin\\Hword.exe <sample>' to open the sample."""

    def start(self, path):
        word = self.get_path("Hangul (Korean) Word Processor File 5.x")
        return self.execute(word, args=[path], mode="office", trigger=f"file:{path}")
