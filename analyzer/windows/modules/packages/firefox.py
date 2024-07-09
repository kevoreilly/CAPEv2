# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Firefox(Package):
    """Firefox analysis package."""

    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
    ]
    summary = "Open the URL in firefox."
    description = """Use firefox.exe to open the supplied url."""

    def start(self, url):
        firefox = self.get_path("firefox.exe")
        # pass the URL instead of a filename in this case
        return self.execute(firefox, f'"{url}"', url)
