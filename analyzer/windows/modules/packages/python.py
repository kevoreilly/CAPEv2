# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS
from lib.common.exceptions import CuckooPackageError


class Python(Package):
    """Python analysis package."""

    PATHS = [("HomeDrive", "Python*", "python.exe"), ("SystemRoot", "py.exe")]
    summary = "Executes sample file with python."
    description = f"""Uses python.exe or py.exe to run a python script.
    If the '{OPT_ARGUMENTS}' option is set, the contents will be used as arguments to the python script."""
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        # Try getting python or py as a backup
        try:
            python = self.get_path_glob("python.exe")
        except CuckooPackageError:
            python = self.get_path_glob("py.exe")

        arguments = self.options.get(OPT_ARGUMENTS, "")

        path = check_file_extension(path, ".py")
        return self.execute(python, f"{path} {arguments}", path)
