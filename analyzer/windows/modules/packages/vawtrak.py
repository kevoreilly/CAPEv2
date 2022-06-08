# Andriy :P

import os
import shutil
from subprocess import call

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class IE(Package):
    """Internet Explorer analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, path):
        iexplore = self.get_path("Internet Explorer")
        # pass the URL instead of a filename in this case
        self.execute(iexplore, '"about:blank"', "about:blank")

        args = self.options.get("arguments")
        appdata = self.options.get("appdata")
        runasx86 = self.options.get("runasx86")

        # If the file doesn't have an extension, add .exe
        # See CWinApp::SetCurrentHandles(), it will throw
        # an exception that will crash the app if it does
        # not find an extension on the main exe's filename
        path = check_file_extension(path, ".exe")

        if appdata:
            # run the executable from the APPDATA directory, required for some malware
            basepath = os.getenv("APPDATA")
            newpath = os.path.join(basepath, os.path.basename(path))
            shutil.copy(path, newpath)
            path = newpath
        if runasx86:
            # ignore the return value, user must have CorFlags.exe installed in the guest VM
            call(["CorFlags.exe", path, "/32bit+"])
        return self.execute(path, args, path)
