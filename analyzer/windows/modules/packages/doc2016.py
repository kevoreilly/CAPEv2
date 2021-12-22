# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class DOC2016(Package):
    """Word analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "WINWORD.EXE"),
    ]

    def start(self, path):
        word = self.get_path_glob("Microsoft Office Word")
        path = check_file_extension(path, ".doc")
        return self.execute(word, f'"{path}" /q /dde /n', path)
