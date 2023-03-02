# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import subprocess

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class Msix(Package):
    """MSIX/MsixBundle analysis package."""

    PATHS = [
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v*.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]

    # https://github.com/Microsoft/Terminal#installing-and-running-windows-terminal
    # NOTE: If you are using PowerShell 7+, please run
    # Import-Module Appx -UseWindowsPowerShell
    # before using Add-AppxPackage.
    # Add-AppxPackage Microsoft.WindowsTerminal_<versionNumber>.msixbundle

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".msix")

        ps_version = "5"
        try:
            ps_version = subprocess.check_output([powershell, "(Get-host).version.Major"], universal_newlines=True)
        except Exception as e:
            print("Can't get PowerShell version, assuming we are on V5: %s", e)

        ps_7_command = ""
        if ps_version.startswith("7"):
            ps_7_command = "Import-Module Appx -UseWindowsPowerShell"

        args = f'-NoProfile -ExecutionPolicy bypass {ps_7_command} Add-AppPackage -path "{path}"'
        return self.execute(powershell, args, path)
