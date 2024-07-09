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
    summary = "Execute a .wsf file using wscript.exe."
    description = """Use wscript.exe to run a .wsf file.
    The .wsf filename extension will be added automatically."""

    def start(self, path):
        wscript = self.get_path("wscript.exe")
        # Enforce the .wsf file extension as is required by wscript.
        path = check_file_extension(path, ".wsf")
        return self.execute(wscript, f'"{path}"', path)
