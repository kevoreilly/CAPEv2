# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
from shutil import copyfile
from lib.common.abstracts import Package


class VBSJSE(Package):
    """VBS/JSE analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        # We are here bcz of no extension
        copyfile(path, path + ".vbe")
        copyfile(path, path + ".jse")
        self.execute(wscript, '"%s.vbe"' % path, path + ".vbe")
        return self.execute(wscript, '"%s.jse"' % path, path + ".jse")
