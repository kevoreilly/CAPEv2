from __future__ import absolute_import

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

        return self.execute(wmplayer, "\"%s\" /q" % path, path)
