# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class Python(Package):
    """Python analysis package."""

    PATHS = [
        ("HomeDrive", "Python*", "python.exe"),
        ("SYSTEMROOT", "py.exe")
    ]

    def start(self, path):
        python = self.get_path_glob("Python")
        arguments = self.options.get("arguments", "")
        return self.execute(python, "%s %s" % (path, arguments), path)
