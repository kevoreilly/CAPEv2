# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class WSF(Package):
    """Windows Scripting File analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        # Enforce the .wsf file extension as is required by wscript.
        path = check_file_extension(path, ".wsf")
        return self.execute(wscript, f'"{path}"', path)
