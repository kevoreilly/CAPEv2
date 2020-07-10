# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)


class HTA(Package):
    """HTA file analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "mshta.exe"),
    ]

    def start(self, path):
        mshta = self.get_path("mshta.exe")

        if not path.endswith(".hta"):
            os.rename(path, path + ".hta")
            path += ".hta"

        return self.execute(mshta, '"%s"' % path, path)
