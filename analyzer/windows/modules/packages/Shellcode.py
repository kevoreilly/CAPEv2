# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package


class Shellcode(Package):
    """32-bit Shellcode analysis package."""

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options["procdump"] = "0"

    def start(self, path):
        offset = self.options.get("offset")
        loaderpath = "bin\\loader.exe"
        args = f"shellcode {path}"
        if offset:
            args += f" {offset}"
        # we need to move out of the analyzer directory
        # due to a check in monitor dll
        basepath = os.path.dirname(path)
        newpath = os.path.join(basepath, os.path.basename(loaderpath))
        shutil.copy(loaderpath, newpath)

        return self.execute(newpath, args, newpath)
