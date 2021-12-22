# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class Unpacker_Regsvr(Package):
    """CAPE Unpacker DLL analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["unpacker"] = "1"
        self.options["procdump"] = "0"
        self.options["injection"] = "0"

    def start(self, path):
        regsvr32 = self.get_path("regsvr32.exe")
        arguments = self.options.get("arguments")

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        args = path
        if arguments:
            args += f" {arguments}"

        return self.execute(regsvr32, args, path)
