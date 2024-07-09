# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_INJECTION, OPT_PROCDUMP, OPT_UNPACKER


class PS1(Package):
    """PowerShell Unpacker analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "WindowsPowerShell", "v*.0", "powershell.exe"),
    ]
    summary = "Execute a sample file with powershell."
    description = """Use 'powershell -NoProfile -ExecutionPolicy bypass -File <sample>'
    to run a .ps1 file.
    Turns off procdump and injection.
    The .ps1 filename extension will be added automatically."""

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options[OPT_UNPACKER] = "1"
        self.options[OPT_PROCDUMP] = "0"
        self.options[OPT_INJECTION] = "0"

    def start(self, path):
        powershell = self.get_path_glob("PowerShell")
        path = check_file_extension(path, ".ps1")
        args = f'-NoProfile -ExecutionPolicy bypass -File "{path}"'
        return self.execute(powershell, args, path)
