# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package


class JS_ANTIVM(Package):
    """JavaScript analysis package, with anti-VM technique prevention.."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        # Determine if the submitter wants the sample to be monitored
        free = self.options.get("free", False)

        # We will be temporarily setting this option so that the background processes will not be monitored.
        self.options["free"] = 1

        # Start 20 Calculator windows
        for _ in range(20):
            calc = os.path.join("C:\\windows", "system32", "calc.exe")
            self.execute(calc, "", path)

        # If the user did not request the monitor to be disabled, enable it
        if not free:
            self.options["free"] = 0

        wscript = self.get_path("wscript.exe")
        args = f'"{path}"'
        ext = os.path.splitext(path)[-1].lower()
        if ext not in (".js", ".jse"):
            if os.path.isfile(path) and open(path, "rt").read(4) == "#@~^":
                os.rename(path, f"{path}.jse")
                path = f"{path}.jse"
            else:
                os.rename(path, f"{path}.js")
                path = f"{path}.js"
        args = f'"{path}"'
        return self.execute(wscript, args, path)
