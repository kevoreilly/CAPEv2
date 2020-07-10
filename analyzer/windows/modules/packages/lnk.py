# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
from lib.common.abstracts import Package


class LNK(Package):
    """LNK analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        if "." not in os.path.basename(path):
            new_path = path + ".lnk"
            os.rename(path, new_path)
            path = new_path

        cmd_path = self.get_path("cmd.exe")
        cmd_args = '/c start /wait "" "{0}"'.format(path)
        return self.execute(cmd_path, cmd_args, path)
