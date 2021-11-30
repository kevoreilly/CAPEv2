# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)


class XLST(Package):
    """XSLT file analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wbem", "wmic.exe"),
        ("SystemRoot", "SysWOW64", "wbem", "wmic.exe"),
    ]

    def start(self, path):
        wmic = self.get_path("wmic.exe")

        if not path.endswith(".xsl"):
            os.rename(path, path + ".xsl")
            path += ".xsl"

        return self.execute(wmic, 'process LIST /FORMAT:"%s"' % path, path)
