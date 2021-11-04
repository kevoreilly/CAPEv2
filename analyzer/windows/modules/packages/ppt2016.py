# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class PPT2007(Package):
    """PowerPoint analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "POWERPNT.EXE"),
    ]

    def start(self, path):
        powerpoint = self.get_path_glob("Microsoft Office PowerPoint")
        return self.execute(powerpoint, '/s "%s"' % path, path)
