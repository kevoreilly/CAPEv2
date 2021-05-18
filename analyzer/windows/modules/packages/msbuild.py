# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package

class MSBUILD(Package):
    """msbuild analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("SystemRoot", "Microsoft.NET", "Framework", "v4.0.30319", "msbuild.exe"),
    ]

    def start(self, path):
        msbuild = self.get_path_glob("msbuild.exe")
        return self.execute(msbuild, '"%s"' % path, path)
