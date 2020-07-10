# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package

# Originally proposed by David Maciejak.


class PS1(Package):
    """PowerShell analysis package."""

    PATHS = [
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")

        if not path.endswith(".ps1"):
            os.rename(path, path + ".ps1")
            path += ".ps1"

        args = '-NoProfile -ExecutionPolicy bypass -File "{0}"'.format(path)
        return self.execute(powershell, args, path)
