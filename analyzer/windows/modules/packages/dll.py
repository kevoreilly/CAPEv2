# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import os
import shutil

from lib.common.abstracts import Package
from lib.common.common import check_file_extension

log = logging.getLogger(__name__)


class Dll(Package):
    """DLL analysis package."""

    PATHS = [
        ("SystemRoot", "System32", "rundll32.exe"),
    ]

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "")
        arguments = self.options.get("arguments", "")
        dllloader = self.options.get("dllloader")
        dll_multi = self.options.get("dll_multi", False)
        max_dll_exports = int(self.options.get("max_dll_exports", 5))
        if max_dll_exports <= 0:
            max_dll_exports = 5

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        # If we just want a DLL function by a single function, a single ordinal or an ordinal range
        if not dll_multi or dll_multi.lower() in ["false", "no", "off"]:
            if not function:
                function = "#1"
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

        # If we want to launch multiple functions by name or dynamically launch DLL functions by their export name
        else:
            # Allow ability to receive multiple entry points by submission, through the use of a pipe
            function = set([item for item in function.split("|") if item])
            if not function:
                try:
                    from pefile import PE, PEFormatError
                    # We have a DLL file, but no user specified function(s) to run. let's try to pick a few...
                    dll_parsed = None
                    try:
                        dll_parsed = PE(data=open(path, "rb").read())
                    except PEFormatError as e:
                        log.warning(f"Could not parse PE file due to {e}")

                    if dll_parsed and hasattr(dll_parsed, "DIRECTORY_ENTRY_EXPORT"):
                        # Do we have any exports?
                        for export_symbol in dll_parsed.DIRECTORY_ENTRY_EXPORT.symbols:
                            if export_symbol.name is not None:
                                if type(export_symbol.name) == str:
                                    function.add(export_symbol.name)
                                elif type(export_symbol.name) == bytes:
                                    function.add(export_symbol.name.decode())
                            else:
                                function.add(f"#{export_symbol.ordinal}")
                except ImportError:
                    log.error("'pefile' module is not installed. On your guest, run 'pip install pefile'.")

            # Wow, seriously? Nothing yet?
            if not function:
                function.add("DllMain")
                function.add("DllRegisterServer")

            # Run them all!
            ret_list = []
            for function_name in list(function)[:max_dll_exports]:
                args = f'"{path}"' if dllloader == "regsvcs.exe" else f'"{path}",{function_name}'
                if arguments:
                    args += f" {arguments}"

                ret_list.append(self.execute(rundll32, args, path))

            available_functions = ",".join(list(function)[max_dll_exports:])
            if available_functions:
                log.info(f"There were {len(function) - max_dll_exports} other exports that were not executed: {available_functions}.")

            return ret_list
