# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class IE(Package):
    """Internet Explorer analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, url):
        iexplore = self.get_path("Internet Explorer")
        # pass the URL instead of a filename in this case
        return self.execute(iexplore, '"%s"' % url, url)
