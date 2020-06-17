# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
from lib.common.abstracts import Package

class TrickBot_doc(Package):
    """TrickBot package (derived from Dump-on-API)"""
    """Word analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.pids = []
        self.options["unpacker"] = "1"
        self.options["procdump"] = "0"

    def start(self, path):
        word = self.get_path_glob("Microsoft Office Word")
        if "." not in os.path.basename(path):
            new_path = path + ".doc"
            os.rename(path, new_path)
            path = new_path

        return self.execute(word, "\"%s\" /q" % path, path)
