# CAPE - Config And Payload Extraction
# Copyright(C) 2015-2018 Context Information Security. (kevin.oreilly@contextis.com)
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil

from lib.common.abstracts import Package

class Debugger_dll(Package):
    """CAPE Debugger_DLL analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "rundll32.exe"),
    ]

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.config = config
        self.options = options
        self.options["debugger"] = "1"

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "#1")
        arguments = self.options.get("arguments")
        dllloader = self.options.get("dllloader")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        if ext != ".dll":
            new_path = path + ".dll"
            os.rename(path, new_path)
            path = new_path

        args = "{0},{1}".format(path, function)
        if arguments:
            args += " {0}".format(arguments)

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        return self.execute(rundll32, args, path)
