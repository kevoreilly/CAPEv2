# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class CHM(Package):
    """Chm analysis package."""

    PATHS = [
        ("SystemRoot", "hh.exe"),
    ]

    def start(self, path):
        hh = self.get_path_glob("hh.exe")
        path = check_file_extension(path, ".chm")
        return self.execute(hh, f'"{path}"', path)
