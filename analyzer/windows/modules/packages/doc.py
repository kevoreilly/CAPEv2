# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.exceptions import CuckooPackageError


class DOC(Package):
    """Word analysis package."""

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]

    def start(self, path):
        # Try getting winword or wordview as a backup
        try:
            word = self.get_path_glob("WINWORD.EXE")
        except CuckooPackageError:
            word = self.get_path_glob("WORDVIEW.EXE")

        path = check_file_extension(path, ".doc")
        return self.execute(word, f'"{path}" /q', path)
