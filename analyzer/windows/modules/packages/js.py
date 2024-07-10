# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.common.constants import OPT_FREE


class JS(Package):
    """JavaScript analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]
    summary = "Executes a .JS file using wscript.exe."
    description = """Uses 'wscript.exe <sample>' to run a .js/.jse file.
    In the case of '.jse' files, first start up 20 calc.exe windows, to thwart
    some anti-vm measures.
    The appropriate file extension will be added automatically."""

    def start(self, path):
        wscript = self.get_path("wscript.exe")
        ext = os.path.splitext(path)[-1].lower()
        if ext not in (".js", ".jse"):
            if ext == ".jse" or os.path.isfile(path) and open(path, "rt").read(4) == "#@~^":
                if ext != ".jse":
                    os.rename(path, f"{path}.jse")
                    path = f"{path}.jse"
                    ext = ".jse"
            else:
                os.rename(path, f"{path}.js")
                path = f"{path}.js"

        if ext == ".jse":
            # antivm fix
            free = self.options.get(OPT_FREE, False)
            # to not track calcs
            self.options[OPT_FREE] = 1
            # fuck antivm
            for _ in range(20):
                # calc
                calc = os.path.join("C:\\windows", "system32", "calc.exe")
                # cl = Process()
                self.execute(calc, "", path)
            if not free:
                self.options[OPT_FREE] = 0

        args = f'"{path}"'
        return self.execute(wscript, args, path)
