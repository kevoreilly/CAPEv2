# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package

class Extraction_Jar(Package):
    """Java analysis package."""
    PATHS = [
        ("ProgramFiles", "Java", "jre*", "bin", "java.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["dll"] = "Extraction.dll"
        self.options["dll_64"] = "Extraction_x64.dll"

    def start(self, path):
        java = self.get_path_glob("Java")
        class_path = self.options.get("class")

        if class_path:
            args = "-cp \"%s\" %s" % (path, class_path)
        else:
            args = "-jar \"%s\"" % path

        return self.execute(java, args, path)
