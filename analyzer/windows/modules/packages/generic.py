# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

from lib.common.abstracts import Package


class Generic(Package):
    """Generic analysis package.
    The sample is started using START command in a cmd.exe prompt.
    """

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        cmd_args = f'/c start /wait "" "{path}"'
        return self.execute(cmd_path, cmd_args, path)
