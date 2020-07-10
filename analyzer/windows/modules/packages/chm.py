# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil

from lib.common.abstracts import Package


class CHM(Package):
    """Chm analysis package."""

    PATHS = [
        ("SystemRoot", "hh.exe"),
    ]

    def start(self, path):
        hh = self.get_path_glob("hh.exe")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .chm extension force it
        # and rename it. This is needed for hh to open correctly.
        if ext != ".chm":
            new_path = path + ".chm"
            os.rename(path, new_path)
            path = new_path

        return self.execute(hh, '"%s"' % path, path)
