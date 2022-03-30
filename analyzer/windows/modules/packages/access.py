# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class ACCESS(Package):
    """ACCESS analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "MSACCESS.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "MSACCESS.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "MSACCESS.EXE"),
        ("ProgramFiles", "Microsoft Office", "MSACCESS.EXE"),
    ]

    def start(self, path):
        access = self.get_path_glob("Microsoft Office Access")
        path = check_file_extension(path, ".accdr")
        return self.execute(access, f'"{path}"', path)
