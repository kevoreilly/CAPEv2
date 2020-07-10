# Copyright (C) 2010-2015 Cuckoo Foundation., Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.common.abstracts import Package


class EML(Package):
    """Outlook EML analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "OUTLOOK.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "OUTLOOK.EXE"),
    ]

    def start(self, path):
        outlook = self.get_path_glob("Microsoft Office Outlook")
        return self.execute(outlook, '/eml "%s"' % path, path)
