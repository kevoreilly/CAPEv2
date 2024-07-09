# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT


class DOC2016(Package):
    """Word analysis package."""

    default_curdir = MSOFFICE_TRUSTED_PATH

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "WINWORD.EXE"),
    ]
    summary = "Open a document file with WINWORD.EXE."
    description = f"""Use 'Office16\\WINWORD.EXE /q /dde /n' to open the sample.
    {TRUSTED_PATH_TEXT}
    The .doc filename extension will be added automatically."""

    def start(self, path):
        word = self.get_path_glob("WINWORD.EXE")
        path = check_file_extension(path, ".doc")
        return self.execute(word, f'"{path}" /q /dde /n', path)
