# Andriy :P

import os
import shutil
from subprocess import call

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_APPDATA, OPT_ARGUMENTS, OPT_RUNASX86


class IE(Package):
    """Internet Explorer analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]
    summary = "Run the supplied executable."
    description = f"""First run 'iexplore.exe about:blank' to open Internet Explorer.
    Then, execute the given sample, passing '{OPT_ARGUMENTS}' if specified.
    Use the '{OPT_APPDATA}' option to run the executable from the APPDATA directory.
    Use the '{OPT_RUNASX86}' option to set the 32BITREQUIRED flag in the PE header,
    using 'CorFlags.exe /32bit+'.
    The .exe filename extension will be added automatically."""
    option_names = (OPT_ARGUMENTS, OPT_APPDATA, OPT_RUNASX86)

    def start(self, path):
        iexplore = self.get_path("iexplore.exe")
        # pass the URL instead of a filename in this case
        self.execute(iexplore, '"about:blank"', "about:blank")

        args = self.options.get(OPT_ARGUMENTS)
        appdata = self.options.get(OPT_APPDATA)
        runasx86 = self.options.get(OPT_RUNASX86)

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
