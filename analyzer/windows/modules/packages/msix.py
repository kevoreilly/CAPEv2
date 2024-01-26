# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import json
import logging
import os
from contextlib import suppress
from pathlib import Path

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.zip_utils import attempt_multiple_passwords, extract_archive, get_file_names

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
            args = f"-NoProfile -ExecutionPolicy bypass {os.getcwd()}\data\msix.ps1 {path}"
            # now we need to get app id and launch it
            return self.execute(powershell, args, powershell)
