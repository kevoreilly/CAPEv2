# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS
from lib.common.exceptions import CuckooPackageError


class Python(Package):
    """Python analysis package."""

    PATHS = [
        ("LocalAppData", "Python", "pythoncore-*", "python.exe"),
        ("LocalAppData", "Programs", "Python", "Python*", "python.exe"),
        ("ProgramFiles", "Python*", "python.exe"),
        ("HomeDrive", "Python*", "python.exe"),
        ("SystemRoot", "py.exe"),
    ]
    summary = "Executes sample file with python."
    description = f"""Uses python.exe or py.exe to run a python script.
    If the '{OPT_ARGUMENTS}' option is set, the contents will be used as arguments to the python script."""
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        # Try getting python or py as a backup, falling back to the active interpreter.
        try:
            python = self.get_path_glob("python.exe")
        except CuckooPackageError:
            try:
                python = self.get_path_glob("py.exe")
            except CuckooPackageError:
                if sys.executable and os.path.isfile(sys.executable):
                    python = sys.executable
                else:
                    raise

        # Set PYTHONHOME to help Python locate its standard library during initialization.
        # Python may fail to load the 'encodings' module, resulting in:
        #       "ModuleNotFoundError: No module named 'encodings'"
        # Skip setting PYTHONHOME for py.exe (which lives in SystemRoot) or installations
        # without a sibling Lib directory (such as virtual environments).
        prev_pythonhome = os.environ.get("PYTHONHOME")
        set_pythonhome = False
        python_home = os.path.dirname(python)
        if os.path.basename(python).lower() != "py.exe" and os.path.isdir(os.path.join(python_home, "Lib")):
            os.environ["PYTHONHOME"] = python_home
            set_pythonhome = True

        arguments = self.options.get(OPT_ARGUMENTS, "")

        path = check_file_extension(path, ".py")
        try:
            return self.execute(python, f"{path} {arguments}", path)
        finally:
            if set_pythonhome:
                if prev_pythonhome is None:
                    os.environ.pop("PYTHONHOME", None)
                else:
                    os.environ["PYTHONHOME"] = prev_pythonhome
