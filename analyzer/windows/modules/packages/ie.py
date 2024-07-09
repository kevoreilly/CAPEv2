# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class IE(Package):
    """Internet Explorer analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]
    summary = "Open the URL in Internet Explorer."
    description = """Use iexplore.exe to open the supplied url."""

    def start(self, url):
        iexplore = self.get_path("Internet Explorer")
        # pass the URL instead of a filename in this case
        return self.execute(iexplore, f'"{url}"', url)
