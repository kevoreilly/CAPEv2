# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil

from lib.common.abstracts import Package


class Dll(Package):
    """DLL analysis package."""

    PATHS = [
        ("SystemRoot", "System32", "rundll32.exe"),
    ]

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function") or "#1"
        arguments = self.options.get("arguments") or ""
        dllloader = self.options.get("dllloader")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        if ext != ".dll":
            new_path = f"{path}.dll"
            os.rename(path, new_path)
            path = new_path

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        try:
            start, end = (int(_.lstrip("#")) for _ in function.replace("..", "-").split("-", 1))
            assert start < end
            args = '/c for /l %i in ({start},1,{end}) do @{rundll32} "{path}",#%i {arguments}'.format(**locals())
            # if there are multiple functions launch them by their ordinal number in a for loop via cmd.exe calling rundll32.exe
            return self.execute("C:\\Windows\\System32\\cmd.exe", args.strip(), path)
        except (ValueError, AssertionError):
            pass

        args = f'"{path}",{function}'
        if arguments:
            args += f" {arguments}"

        return self.execute(rundll32, args, path)
