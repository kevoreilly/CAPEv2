# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class PDF(Package):
    """PDF analysis package."""

    PATHS = [
        ("ProgramFiles", "Adobe", "*a*", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Acrobat DC", "Acrobat", "Acrobat.exe"),
    ]

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options["pdf"] = "1"

    def start(self, path):
        reader = self.get_path_glob("Adobe Reader")
        return self.execute(reader, f'"{path}"', path)
