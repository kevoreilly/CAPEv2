# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class SWF(Package):
    """Shockwave Flash analysis package.
    Download a version of standalone flash from adobe and
    place in bin/ as flashplayer.exe to use

    You can find the bundles you want here:
    https://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
    You want the debug folder (in the zip). The filename will have 'sa' (stand-alone) in it
    """

    summary = "Open an .swf file using flashplayer.exe."
    description = """Use bin\\flashplayer.exe to open a shockwave flash (.swf) file."""

    def start(self, path):
        return self.execute("bin/flashplayer.exe", path, path)
