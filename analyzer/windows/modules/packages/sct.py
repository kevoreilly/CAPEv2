# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPE
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

from lib.common.abstracts import Package


class SCT(Package):
    """SCT analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]

    def start(self, path):
        regsvr32 = self.get_path("regsvr32.exe")
        args = "/u /n /i:{0} scrobj.dll".format(path)

        return self.execute(regsvr32, args, path)
