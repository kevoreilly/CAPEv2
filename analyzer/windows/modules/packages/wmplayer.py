# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

from lib.common.abstracts import Package


class MP3(Package):
    """Windows Media Player analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Windows Media Player", "wmplayer.exe"),
    ]

    def start(self, path):
        wmplayer = self.get_path_glob("Microsoft Media Player")
        if "." not in os.path.basename(path):
            new_path = path + ".mp3"
            os.rename(path, new_path)
            path = new_path

        return self.execute(wmplayer, "\"%s\" /q" % path, path)