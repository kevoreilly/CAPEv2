# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

from lib.common.abstracts import Package
from lib.common.rename import check_file_extension


class XLS(Package):
    """Excel analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
    ]

    def start(self, path):
        path = check_file_extension(path, ".xls")

        excel = self.get_path_glob("Microsoft Office Excel")
        return self.execute(excel, f'"{path}" /dde', path)
