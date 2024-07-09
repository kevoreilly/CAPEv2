# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPE
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class SCT(Package):
    """SCT analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "regsvr32.exe"),
    ]
    summary = "Open the sample with regsvr32.exe scrobj.dll"
    description = """Use 'regsvr32.exe /u /n /i:<sample> scrobj.dll' to launch the sample
        script component."""

    def start(self, path):
        regsvr32 = self.get_path("regsvr32.exe")
        args = f"/u /n /i:{path} scrobj.dll"
        return self.execute(regsvr32, args, path)
