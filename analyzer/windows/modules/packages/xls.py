# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT


class XLS(Package):
    """Excel analysis package."""

    default_curdir = MSOFFICE_TRUSTED_PATH

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
    ]
    summary = "Open the supplied document with EXCEL.EXE."
    description = f"""Use 'EXCEL.EXE <path> /dde' to open the file.
    {TRUSTED_PATH_TEXT}
    The .xls filename extension will be added automatically."""

    def start(self, path):
        if not path.endswith((".xls", ".xlsx")):
            path = check_file_extension(path, ".xls")
        excel = self.get_path_glob("EXCEL.EXE")
        return self.execute(excel, f'"{path}" /dde', path)
