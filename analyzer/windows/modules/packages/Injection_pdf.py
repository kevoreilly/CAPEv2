# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package

class Injection_PDF(Package):
    """PDF analysis package."""
    PATHS = [
        ("ProgramFiles", "Adobe", "*a*", "Reader", "AcroRd32.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["injection"] = "1"
        self.options["procdump"] = "0"

    def start(self, path):
        reader = self.get_path_glob("Adobe Reader")
        return self.execute(reader, "\"%s\"" % path, path)
