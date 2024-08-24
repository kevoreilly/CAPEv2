# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from shutil import copyfile

from lib.common.abstracts import Package


class VBSJSE(Package):
    """VBS/JSE analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]
    summary = "Opens a sample file with wscript.exe."
    description = """Makes two copies of the sample, one with extension .vbe
    and the second with extension .jse.
    Using wscript.exe first opens the .vbe file and then the .jse file.
    """

    def start(self, path):
        wscript = self.get_path("wscript.exe")
        # We are here bcz of no extension
        copyfile(path, f"{path}.vbe")
        copyfile(path, f"{path}.jse")
        self.execute(wscript, f'"{path}.vbe"', f"{path}.vbe")
        return self.execute(wscript, f'"{path}.jse"', f"{path}.jse")
