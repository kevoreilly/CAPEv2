# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import json
import logging
import shlex
import subprocess
from contextlib import suppress
from pathlib import Path

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import (
    attempt_multiple_passwords,
    extract_archive,
    get_file_names,
)

log = logging.getLogger(__name__)

class Msix(Package):
    """MSIX/MsixBundle analysis package."""

    PATHS = [
        ("ProgramFiles", "7-Zip", "7z.exe"),
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v*.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]

    # https://github.com/Microsoft/Terminal#installing-and-running-windows-terminal
    # NOTE: If you are using PowerShell 7+, please run
    # Import-Module Appx -UseWindowsPowerShell
    # before using Add-AppxPackage.
    # Add-AppxPackage Microsoft.WindowsTerminal_<versionNumber>.msixbundle

    def start(self, path):
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".msix")
        orig_path = Path(path)
        seven_zip_path = self.get_path_app_in_path("7z.exe")
        password = self.options.get("password", "infected")
        file_names = get_file_names(seven_zip_path, path)
        args = ""

        if len(file_names) and "config.json" in file_names:
            try_multiple_passwords = attempt_multiple_passwords(self.options, password)
            extract_archive(seven_zip_path, path, orig_path.parent, password, try_multiple_passwords)
            log.debug(f"Extracted {len(file_names)} files from {path} to {orig_path.parent}")

        with suppress(Exception):
            config_path = str(orig_path.with_name("config.json"))
            with open(config_path, "r") as config_file:
                config_data = json.load(config_file)
                script_paths = []
                for application in config_data.get("applications", []):
                    script_paths.append(application.get("startScript", {}).get("scriptPath", ""))

                if script_paths:
                    path = str(orig_path.with_name(script_paths[0]))
                    args = f'-NoProfile -ExecutionPolicy bypass -File "{path}"'
                    log.debug(f"msix file contains script {path}")

        if not args:
            ps_version = "5"
            app_id = ""
            last_app_id = ""
            try:
                ps_version = subprocess.check_output(
                    [powershell, "(Get-host).version.Major"], universal_newlines=True, startupinfo=self.startupinfo
                )
            except Exception as e:
                print("Can't get PowerShell version, assuming we are on V5: %s", e)

            ps_7_command = ""
            if ps_version.startswith("7"):
                ps_7_command = "Import-Module Appx -UseWindowsPowerShell"

            try:
                last_app_id = subprocess.check_output(
                    [powershell, "Get-StartApps | Select AppID -last 1 | ForEach-Object {$_.AppID }"],
                    universal_newlines=True,
                    startupinfo=self.startupinfo,
                )
            except Exception as e:
                print("Can't get AppID: %s", e)

            # -WindowStyle hidden
            args = f'-NoProfile -ExecutionPolicy bypass {ps_7_command} Add-AppPackage -path "{path}"'
            # this is just install
            try:
                _ = subprocess.check_output([powershell, *shlex.split(args)], universal_newlines=True, startupinfo=self.startupinfo)
            except Exception as e:
                print("Can't get PowerShell version, assuming we are on V5: %s", e)

            # We need the app ID
            try:
                app_id = subprocess.check_output(
                    [powershell, "Get-StartApps | Select AppID -last 1 | ForEach-Object {$_.AppID }"],
                    universal_newlines=True,
                    startupinfo=self.startupinfo,
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
