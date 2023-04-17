# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError


class Python(Package):
    """Python analysis package."""

    PATHS = [("HomeDrive", "Python*", "python.exe"), ("SystemRoot", "py.exe")]

    def start(self, path):
        # Try getting python or py as a backup
        try:
            python = self.get_path_glob("python.exe")
        except CuckooPackageError:
            python = self.get_path_glob("py.exe")

        arguments = self.options.get("arguments", "")
        return self.execute(python, f"{path} {arguments}", path)
