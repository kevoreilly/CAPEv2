# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension

# Originally proposed by David Maciejak.


class PS1(Package):
    """PowerShell analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".ps1")
        args = f'-NoProfile -ExecutionPolicy bypass -File "{path}"'
        return self.execute(powershell, args, path)
