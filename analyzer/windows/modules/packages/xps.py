# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Xps(Package):
    """XPS analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "xpsrchvw.exe"),
    ]
    summary = "Open the sample file with xpsrchvw.exe."
    description = """Use xpsrchvw.exe to open the supplied sample."""

    def start(self, path):
        xpsrchvw_path = self.get_path("xpsrchvw.exe")
        xpsrchvw_args = f'"{path}"'
        return self.execute(xpsrchvw_path, xpsrchvw_args, path)
