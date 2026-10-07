# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class Msi(Package):
    """MSI analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "msiexec.exe"),
    ]
    summary = "Executes a sample with msiexec.exe."
    description = """Uses 'msiexec.exe /I <sample> /qb ACCEPTEULA=1 LicenseAccepted=1'
    to run the sample."""

    def start(self, path):
        path = check_file_extension(path, ".msi")
        msi_path = self.get_path("msiexec.exe")
        msi_args = f'/I "{path}" /qb ACCEPTEULA=1 LicenseAccepted=1'
        return self.execute(msi_path, msi_args, path)
