# CAPE - Config And Payload Extraction
# Copyright(C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
# See the file 'docs/LICENSE' for copying permission.

import os
from lib.common.abstracts import Package

class Emotet_doc(Package):
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
        self.options["extraction"] = "1"
        self.options["procdump"] = "0"
        self.options["exclude-apis"] = "RegOpenKeyExA"

    def start(self, path):
        word = self.get_path_glob("Microsoft Office Word")
        if "." not in os.path.basename(path):
            new_path = path + ".doc"
            os.rename(path, new_path)
            path = new_path

        return self.execute(word, "\"%s\" /q" % path, path)
