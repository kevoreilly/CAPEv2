# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS


class CHM(Package):
    """Chm analysis package."""

    PATHS = [
        ("SystemRoot", "hh.exe"),
    ]
    summary = "Opens the compiled help file with hh.exe."
    description = """Uses 'hh.exe <sample>' to open the sample.
    The .chm filename extension will be added automatically."""
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        hh = self.get_path_glob("hh.exe")
        path = check_file_extension(path, ".chm")
        return self.execute(hh, f'"{path}"', path)
