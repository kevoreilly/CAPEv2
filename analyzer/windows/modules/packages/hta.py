# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class HTA(Package):
    """HTA file analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "mshta.exe"),
    ]
    summary = "Executes the sample with mshta.exe."
    description = """Uses 'mshta.exe <sample>' to run a .hta file.
    The .hta filename extension will be added automatically."""

    def start(self, path):
        mshta = self.get_path("mshta.exe")
        path = check_file_extension(path, ".hta")
        return self.execute(mshta, f'"{path}"', path)
