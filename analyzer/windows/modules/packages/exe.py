# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
from subprocess import call

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_APPDATA, OPT_ARGUMENTS, OPT_EXECUTIONDIR, OPT_RUNASX86


class Exe(Package):
    """EXE analysis package."""

    summary = "Run the supplied executable."
    description = f"""Execute the given sample, passing '{OPT_ARGUMENTS}' if specified.
    Use the '{OPT_APPDATA}' option to run the executable from the APPDATA directory.
    Use the '{OPT_RUNASX86}' option to set the 32BITREQUIRED flag in the PE header,
    using 'CorFlags.exe /32bit+'.
    The .exe extension will be added automatically."""
    option_names = (OPT_ARGUMENTS, OPT_APPDATA, OPT_RUNASX86)

    def start(self, path):
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
            self.options[OPT_EXECUTIONDIR] = basepath
        if runasx86:
            # ignore the return value, user must have CorFlags.exe installed in the guest VM
            call(["CorFlags.exe", path, "/32bit+"])
        return self.execute(path, args, path)
