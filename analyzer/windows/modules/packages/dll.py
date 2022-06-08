# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import os
import shutil

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class Dll(Package):
    """DLL analysis package."""

    PATHS = [
        ("SystemRoot", "System32", "rundll32.exe"),
    ]

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "#1")
        arguments = self.options.get("arguments", "")
        dllloader = self.options.get("dllloader")

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        with contextlib.suppress(ValueError, AssertionError):
            start, end = (int(_.lstrip("#")) for _ in function.replace("..", "-").split("-", 1))
            assert start < end
            args = '/c for /l %i in ({start},1,{end}) do @{rundll32} "{path}",#%i {arguments}'.format(**locals())
            # if there are multiple functions launch them by their ordinal number in a for loop via cmd.exe calling rundll32.exe
            return self.execute("C:\\Windows\\System32\\cmd.exe", args.strip(), path)

        args = f'"{path}"' if dllloader == "regsvcs.exe" else f'"{path}",{function}'
        if arguments:
            args += f" {arguments}"

        return self.execute(rundll32, args, path)
