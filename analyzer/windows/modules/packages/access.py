# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class ACCESS(Package):
    """ACCESS analysis package."""

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "MSACCESS.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "MSACCESS.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "MSACCESS.EXE"),
        ("ProgramFiles", "Microsoft Office", "MSACCESS.EXE"),
    ]
    summary = "Open an .accdr file using MSACCESS.EXE."
    description = """Use MSACCESS.EXE to open a .accdr file.
    The .accdr filename extension will be added automatically."""

    def start(self, path):
        access = self.get_path_glob("MSACCESS.EXE")
        path = check_file_extension(path, ".accdr")
        return self.execute(access, f'"{path}"', path)
