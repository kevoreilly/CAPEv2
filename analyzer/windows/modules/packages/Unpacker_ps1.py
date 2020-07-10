# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package


class PS1(Package):
    """PowerShell Unpacker analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["unpacker"] = "1"
        self.options["procdump"] = "0"
        self.options["injection"] = "0"

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")

        if not path.endswith(".ps1"):
            os.rename(path, path + ".ps1")
            path += ".ps1"

        args = '-NoProfile -ExecutionPolicy bypass -File "{0}"'.format(path)
        return self.execute(powershell, args, path)
