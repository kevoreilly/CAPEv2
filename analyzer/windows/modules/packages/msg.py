# Copyright (C) 2010-2015 Cuckoo Foundation., Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class MSG(Package):
    """Outlook MSG analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "OUTLOOK.EXE"),
    ]
    summary = "Open a .msg file with MS Outlook."
    description = """Use 'OUTLOOK.EXE /f <sample>' to open a .msg file."""

    def start(self, path):
        outlook = self.get_path_glob("OUTLOOK.EXE")
        return self.execute(outlook, f'/f "{path}"', path)
