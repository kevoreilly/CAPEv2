# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension

_OPT_PWSH = "pwsh"


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
    summary = "Execute a sample file with powershell."
    description = f"""Use 'powershell -NoProfile -ExecutionPolicy bypass -File <sample>'
    to run a .ps1 file.
    If the '{_OPT_PWSH}' option is set, Powershell Core (PS v7) will be preferred.
    The .ps1 filename extension will be added automatically."""
    option_names = (_OPT_PWSH,)

    def get_paths(self):
        """Return list of paths to search for the PowerShell executable.

        If the user selected the option, insert PowerShell Core path at the start of
        the list.
        """
        if self.options.get(_OPT_PWSH):
            return self.POWERSHELL_CORE + self.PATHS
        return self.PATHS

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".ps1")
        args = f'-NoProfile -ExecutionPolicy bypass -File "{path}"'
        return self.execute(powershell, args, path)
