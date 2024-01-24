# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import shlex
import subprocess

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.exceptions import CuckooPackageError


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
        app_id = ""
        last_app_id = ""
        try:
            ps_version = subprocess.check_output([powershell, "(Get-host).version.Major"], universal_newlines=True)
        except Exception as e:
            print("Can't get PowerShell version, assuming we are on V5: %s", e)

        ps_7_command = ""
        if ps_version.startswith("7"):
            ps_7_command = "Import-Module Appx -UseWindowsPowerShell"

        try:
            last_app_id = subprocess.check_output(
                [powershell, "Get-StartApps | Select AppID -last 1 | ForEach-Object {$_.AppID }"], universal_newlines=True
            )
        except Exception as e:
            print("Can't get AppID: %s", e)

        args = f'-NoProfile -ExecutionPolicy bypass {ps_7_command} Add-AppPackage -path "{path}"'
        # this is just install
        try:
            ps_version = subprocess.check_output([powershell, *shlex.split(args)], universal_newlines=True)
        except Exception as e:
            print("Can't get PowerShell version, assuming we are on V5: %s", e)

        # We need the app ID
        try:
            app_id = subprocess.check_output(
                [powershell, "Get-StartApps | Select AppID -last 1 | ForEach-Object {$_.AppID }"], universal_newlines=True
            )
        except Exception as e:
            print("Can't get AppID: %s", e)

        # app_id should be our recently installer MSIX app
        if last_app_id == app_id:
            raise CuckooPackageError("MSIX package wasn't installed properly, see screenshots and logs for more details")

        args = f"-NoProfile -ExecutionPolicy bypass {ps_7_command} explorer shell:appsFolder\\{app_id}"

        # ToDo abort analysis here somehow

        # now we need to get app id and launch it
        return self.execute(powershell, args, path)
