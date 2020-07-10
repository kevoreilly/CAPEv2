# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class Chrome(Package):
    """Chrome analysis package."""

    PATHS = [
        ("ProgramFiles", "Google", "Chrome", "Application", "chrome.exe"),
    ]

    def start(self, url):
        chrome = self.get_path("Google Chrome")
        # pass the URL instead of a filename in this case
        return self.execute(chrome, '"%s"' % url, url)
