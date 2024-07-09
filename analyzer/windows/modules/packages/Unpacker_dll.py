# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS, OPT_DLLLOADER, OPT_FUNCTION, OPT_INJECTION, OPT_UNPACKER
from modules.packages.dll import DLL_OPTION_TEXT, DLL_OPTIONS


class Unpacker_dll(Package):
    """CAPE Unpacker DLL analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "rundll32.exe"),
    ]
    summary = "Execute a .dll file using rundll32.exe."
    description = f"""Use rundll32.exe with the '/wait' option to run a .lnk file.
    {DLL_OPTION_TEXT}
    Set options '{OPT_INJECTION}=0' and '{OPT_UNPACKER}=1'.
    The .dll filename extension will be added automatically."""
    option_names = DLL_OPTIONS

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options[OPT_UNPACKER] = "1"
        self.options[OPT_INJECTION] = "0"

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get(OPT_FUNCTION, "#1")
        arguments = self.options.get(OPT_ARGUMENTS)
        dllloader = self.options.get(OPT_DLLLOADER)

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        args = f"{path},{function}"
        if arguments:
            args += f" {arguments}"

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        return self.execute(rundll32, args, path)
