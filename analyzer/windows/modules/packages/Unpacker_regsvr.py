# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS, OPT_INJECTION, OPT_PROCDUMP, OPT_UNPACKER


class Unpacker_Regsvr(Package):
    """CAPE Unpacker DLL analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]
    summary = "Execute function(s) in a DLL file using regsvr32.exe."
    description = """Use regsvr32.exe to run one or more functions in a .dll file.
    Turn off procdump and injection.
    The .dll filename extension will be added automatically."""
    option_names = (OPT_ARGUMENTS,)

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
        regsvr32 = self.get_path("regsvr32.exe")
        arguments = self.options.get(OPT_ARGUMENTS)

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        args = path
        if arguments:
            args += f" {arguments}"

        return self.execute(regsvr32, args, path)
