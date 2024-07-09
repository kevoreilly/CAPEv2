# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://lolbas-project.github.io/lolbas/Binaries/Cmstp/

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class INF(Package):
    """INF analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("SystemRoot", "System32", "cmstp.exe"),
        ("SystemRoot", "SysWOW64", "cmstp.exe"),
    ]
    summary = "Open the sample with cmstp.exe."
    description = """Use 'cmstp.exe /f <sample>' to open the sample
    as a Connection Manager service profile.
    The .inf filename extension will be added automatically."""

    def start(self, path):
        cmstp = self.get_path_glob("cmstp.exe")
        path = check_file_extension(path, ".inf")
        return self.execute(cmstp, f'/s "{path}"', path)
