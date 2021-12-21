# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class UPX_dll(Package):
    """CAPE UPX DLL analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "rundll32.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["upx"] = "1"

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "#1")
        arguments = self.options.get("arguments")
        dllloader = self.options.get("dllloader")

        path = check_file_extension(path, ".dll")

        args = f"{path},{function}"
        if arguments:
            args += f" {arguments}"

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        return self.execute(rundll32, args, path)
