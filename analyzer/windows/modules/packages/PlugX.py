# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil
import logging
from subprocess import call
from lib.common.abstracts import Package

log = logging.getLogger(__name__)


class PlugX(Package):
    """CAPE PlugX analysis package."""

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.pids = []
        self.options["dll"] = "PlugX.dll"

        log.info("Timeout: " + str(self.config.timeout))

        # if self.config.timeout > 10:
        #    self.config.timeout = 5
        #    log.info("Timeout reset to: " + str(self.config.timeout))

    def start(self, path):
        args = self.options.get("arguments")
        appdata = self.options.get("appdata")
        runasx86 = self.options.get("runasx86")
        self.options["dll"] = "PlugX.dll"

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
            basepath = os.getenv("APPDATA")
            newpath = os.path.join(basepath, os.path.basename(path))
            shutil.copy(path, newpath)
            path = newpath
        if runasx86:
            # ignore the return value, user must have CorFlags.exe installed in the guest VM
            call(["CorFlags.exe", path, "/32bit+"])
        return self.execute(path, args, path)
