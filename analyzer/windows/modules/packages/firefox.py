# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class Firefox(Package):
    """Firefox analysis package."""

    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
    ]

    def start(self, url):
        firefox = self.get_path("Mozilla Firefox")
        # pass the URL instead of a filename in this case
        return self.execute(firefox, '"%s"' % url, url)
