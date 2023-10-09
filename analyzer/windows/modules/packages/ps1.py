# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class PS1(Package):
    """PowerShell analysis package."""

    POWERSHELL_CORE = [
        # PS v7 (Powershell Core) optional.
        ("ProgramFiles", "PowerShell", "*", "pwsh.exe"),
    ]
    PATHS = [
        # PS <= 5
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v*.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]

    def get_paths(self):
        """Return list of paths to search for the PowerShell executable.

        If the user selected the option, insert PowerShell Core path at the start of
        the list.
        """
        if self.options.get("pwsh"):
            return self.POWERSHELL_CORE + self.PATHS
        return self.PATHS

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".ps1")
        args = f'-NoProfile -ExecutionPolicy bypass -File "{path}"'
        return self.execute(powershell, args, path)
