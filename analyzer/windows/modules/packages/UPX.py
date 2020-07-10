# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil

from lib.common.abstracts import Package


class UPX(Package):
    """CAPE UPX analysis package."""

    # PATHS = [
    #    ("SystemRoot", "system32"),
    # ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.pids = []
        self.options["upx"] = "1"

    def start(self, path):
        arguments = self.options.get("arguments")
        appdata = self.options.get("appdata")

        # If the file doesn't have an extension, add .exe
        if "." not in os.path.basename(path):
            new_path = path + ".exe"
            os.rename(path, new_path)
            path = new_path

        if appdata:
            # run the executable from the APPDATA directory, required for some malware
            basepath = os.getenv("APPDATA")
            newpath = os.path.join(basepath, os.path.basename(path))
            shutil.copy(path, newpath)
            path = newpath

        return self.execute(path, arguments, path)
