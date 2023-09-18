# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class PPT(Package):
    """PowerPoint analysis package."""

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "POWERPNT.EXE"),
    ]

    def start(self, path):
        powerpoint = self.get_path_glob("POWERPNT.EXE")
        return self.execute(powerpoint, f'/s "{path}"', path)
