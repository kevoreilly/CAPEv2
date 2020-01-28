# CAPE - Config And Payload Extraction
# Copyright(C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil
from subprocess import call
from lib.common.abstracts import Package

class Emotet(Package):
    """Emotet analysis package."""

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.pids = []
        self.options["extraction"] = "1"
        self.options["procdump"] = "0"
        self.options["single-process"] = "1"
        self.options["exclude-apis"] = "RegOpenKeyExA:SendMessageA"

    def start(self, path):
        args = self.options.get("arguments")
        appdata = self.options.get("appdata")
        runasx86 = self.options.get("runasx86")

        # If the file doesn't have an extension, add .exe
        # See CWinApp::SetCurrentHandles(), it will throw
        # an exception that will crash the app if it does
        # not find an extension on the main exe's filename
        if "." not in os.path.basename(path):
            new_path = path + ".exe"
            os.rename(path, new_path)
            path = new_path

        if appdata:
            # run the executable from the APPDATA directory, required for some malware
            basepath = os.getenv('APPDATA')
            newpath = os.path.join(basepath, os.path.basename(path))
            shutil.copy(path, newpath)
            path = newpath
        return self.execute(path, args, path)
