# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class Xps(Package):
    """XPS analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "xpsrchvw.exe"),
    ]

    def start(self, path):
        xpsrchvw_path = self.get_path("xpsrchvw.exe")
        xpsrchvw_args = '"{0}"'.format(path)
        return self.execute(xpsrchvw_path, xpsrchvw_args, path)
