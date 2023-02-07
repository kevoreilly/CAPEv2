# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class MHT(Package):
    """MHT file analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, path):
        iexplore = self.get_path("iexplore.exe")

        # Travelling inside malware universe you should bring a towel with you.
        # If a file detected as HTML is submitted without a proper extension,
        # or without an extension at all (are you used to name samples with hash?),
        # IE is going to open it as a text file, so your precious sample will not
        # be executed.
        # We help you sample to execute renaming it with a proper extension.
        path = check_file_extension(path, ".mht")
        return self.execute(iexplore, f'"{path}"', path)
