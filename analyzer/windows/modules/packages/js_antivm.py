# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package


class JS_ANTIVM(Package):
    """JavaScript analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        free = self.options.get("free", False)
        # to not track calcs
        self.options["free"] = 1
        # fuck antivm
        for _ in range(50):
            # calc
            calc = os.path.join("c:\\windows", "system32", "calc.exe")
            # cl = Process()
            self.execute(calc, "", path)
        if free is False:
            self.options["free"] = 0
        wscript = self.get_path("wscript.exe")
        args = '"%s"' % path
        ext = os.path.splitext(path)[-1].lower()
        if ext != ".js" and ext != ".jse":
            if os.path.isfile(path) and "#@~^" == open(path, "rt").read(4):
                os.rename(path, path + ".jse")
                path = path + ".jse"
            else:
                os.rename(path, path + ".js")
                path = path + ".js"
        args = '"%s"' % path
        return self.execute(wscript, args, path)
