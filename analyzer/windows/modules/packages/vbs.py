# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package

# Originally proposed by kidrek:
# https://github.com/cuckoobox/cuckoo/pull/136


class VBS(Package):
    """VBS analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Check file extension.
        # If the file doesn't have the proper .vbs extension force it
        # and rename it. This is needed for wscript to execute correctly.
        ext = os.path.splitext(path)[-1].lower()
        if ext != ".vbs" and ext != ".vbe":
            if os.path.isfile(path) and b"#@~^" in open(path, "rb").read(100):
                os.rename(path, path + ".vbe")
                path = path + ".vbe"
            else:
                os.rename(path, path + ".vbs")
                path = path + ".vbs"

        return self.execute(wscript, '"%s"' % path, path)
