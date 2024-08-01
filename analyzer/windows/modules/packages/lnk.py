# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class LNK(Package):
    """Windows LNK analysis package via powershell."""

    PATHS = [
        # PS <= 5
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v*.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]
    summary = "Executes a sample file with powershell."
    description = "Uses 'powershell Start-Process -FilePath <sample>' to run a .lnk file."

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".lnk")
        args = f'Start-Process -FilePath "{path}"'
        return self.execute(powershell, args, path)
