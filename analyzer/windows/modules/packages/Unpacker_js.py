# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package


class Unpacker_JS(Package):
    """JavaScript analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["unpacker"] = "1"
        self.options["procdump"] = "0"
        self.options["injection"] = "0"

    def start(self, path):
        wscript = self.get_path("wscript.exe")
        args = f'"{path}"'
        ext = os.path.splitext(path)[-1].lower()
        if ext not in (".js", ".jse"):
            with open(path, "r") as tmpfile:
                magic_bytes = tmpfile.read(4)
            if magic_bytes == "#@~^":
                os.rename(path, f"{path}.jse")
                path = f"{path}.jse"
            else:
                os.rename(path, f"{path}.js")
                path = f"{path}.js"
        args = f'"{path}"'
        return self.execute(wscript, args, path)
