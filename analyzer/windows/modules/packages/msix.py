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
from lib.common.zip_utils import extract_zip, get_zip_file_names

log = logging.getLogger(__name__)


class Msix(Package):
    """MSIX/MsixBundle analysis package."""

    PATHS = [
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v*.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]
    summary = "Execute a sample .msix file with powershell."
    description = """Use the bundled msix.ps1 powershell script to run a .msix file.
    Default behavior is to run 'powershell.exe -NoProfile -ExecutionPolicy bypass data\\msix.ps1 <sample>
    However, if the .msix package contains a file config.json, that config file will be
    examined for applications/startScript/scriptPath.  If any are found, the first will be used
    and the analyzer will run 'powershell.exe -NoProfile -ExecutionPolicy bypass -File "path"'.
    The .msix extension will be added automatically."""

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".msix")
        orig_path = Path(path)
        file_names = get_zip_file_names(path)
        args = ""

        if len(file_names) and "config.json" in file_names:
            extract_zip(path, orig_path.parent)
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
