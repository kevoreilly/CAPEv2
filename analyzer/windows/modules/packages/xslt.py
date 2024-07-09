# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class XSLT(Package):
    """XSLT file analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wbem", "wmic.exe"),
        ("SystemRoot", "SysWOW64", "wbem", "wmic.exe"),
    ]
    summary = "Open sample file using wmic.exe."
    description = """Use 'wmic.exe process LIST /FORMAT:"<sample>"' to detonate any
    code embedded in the xml sample.
    The .xsl filename extension will be added automatically."""

    def start(self, path):
        wmic = self.get_path("wmic.exe")
        path = check_file_extension(path, ".xsl")
        return self.execute(wmic, f'process LIST /FORMAT:"{path}"', path)
