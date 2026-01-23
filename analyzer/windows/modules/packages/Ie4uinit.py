# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/
# https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/
# https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/

import os
import shutil
from lib.common.abstracts import Package


class IE4uinit(Package):
    """Ie4uinit analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "ie4uinit.exe"),
        # ("Windows", "SysWOW64", "ie4uinit.exe"),
    ]
    summary = "Executes commands from a specially prepared ie4uinit.inf file."
    description = """Executes commands from a specially prepared ie4uinit.inf file."""

    def start(self, path):
        # rundll32.exe ieadvpack.dll,LaunchINFSection test.inf,,1, <- Requires DefaultInstall as entry point
        # check if named " ie4uinit.inf"
        ie4uinit = self.get_path_app_in_path("ie4uinit.exe")
        dirname = os.path.dirname(path)
        local_ie4uinit = os.path.join(dirname, "ie4uinit.exe")
        shutil.copy(ie4uinit, local_ie4uinit)
        ie4uinit = local_ie4uinit
        if not path.endswith("ie4uinit.inf"):
            new_file = os.path.join(dirname, "ie4uinit.inf")
            shutil.copy(path, new_file)
            path = new_file
        return self.execute(ie4uinit, "-BaseSettings", path)
