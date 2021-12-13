# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import logging

from lib.common.abstracts import Package
from lib.common.common import check_file_extension

log = logging.getLogger(__name__)


class WSF(Package):
    """Windows Scripting File analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Enforce the .wsf file extension as is required by wscript.
        path = check_file_extension(path, ".wsf")

        return self.execute(wscript, f'"{path}"', path)
