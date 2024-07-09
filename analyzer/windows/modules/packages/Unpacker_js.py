# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.common.constants import OPT_INJECTION, OPT_PROCDUMP, OPT_UNPACKER


class Unpacker_JS(Package):
    """JavaScript analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]
    summary = "Execute a .JS file using wscript.exe."
    description = f"""Use wscript.exe to run a .js/.jse file.
    Turn off the '{OPT_PROCDUMP}' and {OPT_INJECTION} options.
    The appropriate filename extension will be added automatically."""

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options[OPT_UNPACKER] = "1"
        self.options[OPT_PROCDUMP] = "0"
        self.options[OPT_INJECTION] = "0"

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
