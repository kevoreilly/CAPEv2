# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import os
import shutil

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import DLL_OPTIONS, OPT_ARGUMENTS, OPT_DLLLOADER, OPT_FUNCTION

log = logging.getLogger(__name__)

_OPT_ENABLE_MULTI = "enable_multi"
_OPT_MAX_DLL_EXPORTS = "max_dll_exports"
_OPT_USE_EXPORT_NAME = "use_export_name"
MAX_DLL_EXPORTS_DEFAULT = 8

DLL_OPTION_TEXT = """
Use the 'dllloader' option to set the name of the process loading the DLL (defaults to rundll32.exe).
Use the 'arguments' option to set the arguments to be passed to the exported function(s).
Use the 'function' option to set the name of the exported function/ordinal to execute.
The default function is '#1'.
Can be multiple function/ordinals split by colon. Ex: function=#1:#3 or #2-4
"""


class Dll(Package):
    """DLL analysis package."""

    PATHS = [
        ("SystemRoot", "System32", "rundll32.exe"),
    ]
    summary = "Execute a .DLL file using rundll32.exe."
    description = f"""Use rundll32.exe to execute a function or functions in the DLL file.
    {DLL_OPTION_TEXT}

    Functions to execute may be specified by number, the default is '#1'.
    Use the '{_OPT_ENABLE_MULTI}' option if multiple functions should be executed.
    Function numbers should be separated by a colon, for example: '#1:#3:#5'.
    A range of functions can be specified, for example: '#1..3' or '#2-4'

    Functions to execute may be specified by name, if the '{_OPT_USE_EXPORT_NAME}' option is True.
    The default function name is 'DllMain'
    Specify the '{_OPT_ENABLE_MULTI}' option if multiple functions should be executed.
    Function names should be separated by a colon, for example: 'func1:func2'.

    When '{_OPT_ENABLE_MULTI}' is used and function names are not specified, attempt to identify exported functions.
    If no exported function names were available, default to 'DllMain' and 'DllRegisterServer'.

    By default, at most {MAX_DLL_EXPORTS_DEFAULT} functions will be executed; use the option
    '{_OPT_MAX_DLL_EXPORTS}' to set a different limit.

    The .dll filename extension will be added to the sample name automatically."""
    option_names = sorted(set(DLL_OPTIONS + (_OPT_ENABLE_MULTI, _OPT_USE_EXPORT_NAME, _OPT_MAX_DLL_EXPORTS)))

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        arguments = self.options.get(OPT_ARGUMENTS, "")
        dllloader = self.options.get(OPT_DLLLOADER)

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        path = check_file_extension(path, ".dll")

        if dllloader:
            newname = os.path.join(os.path.dirname(rundll32), dllloader)
            shutil.copy(rundll32, newname)
            rundll32 = newname

        # If user has requested we use something (function, functions, ordinal, ordinal range)
        function = self.options.get(OPT_FUNCTION)

        # Does the user want us to run multiple exports that are available?
        enable_multi = self.options.get(_OPT_ENABLE_MULTI, "")
        if enable_multi.lower() in ("on", "yes", "true"):
            enable_multi = True
        else:
            enable_multi = False

        # Does the user want us to run multiple exports by name?
        use_export_name = self.options.get(_OPT_USE_EXPORT_NAME, "")
        if use_export_name.lower() in ("on", "yes", "true"):
            use_export_name = True
        else:
            use_export_name = False

        run_ordinal_range = False
        run_multiple_functions = False

        max_dll_exports = None
        available_exports = []
        if function:
            # If user has requested we use functions (by name or by ordinal number), separated by colon
            if enable_multi and ":" in function:
                function = function.split(":")
                run_multiple_functions = True

            # If user has requested we use an ordinal range, separated by a hyphen or by ..
            elif enable_multi and ("-" in function or ".." in function):
                run_ordinal_range = True

            # If the user has not enabled multi, but requested multiple functions, log it and default to #1
            elif not enable_multi and (":" in function or "-" in function or ".." in function):
                log.warning(f"You need to enable the `{_OPT_ENABLE_MULTI}` option if you want to run multiple functions.")
                # Setting function to the first ordinal number since the user does not want use to run multiple functions.
                function = "#1"

        # If user has not requested that we use a function(s), we should default to running main export entry or
        # all available exports, up to a limit, if enabled
        else:
            # If the user does not want us to run multiple exports that are available, set function to default
            if not enable_multi:
                if not use_export_name:
                    function = "#1"
                else:
                    function = "DllMain"

            # The user does want us to run multiple functions if we can find them
            else:
                available_exports = list(filter(None, self.config.exports.split(",")))

                # If there are no available exports, default
                if not available_exports:
                    if use_export_name:
                        function = ["DllMain", "DllRegisterServer"]
                        run_multiple_functions = True
                    else:
                        function = "#1"

                # If there are available exports, set limit and determine if we are to use name or number
                else:
                    max_dll_exports = int(self.options.get(_OPT_MAX_DLL_EXPORTS, MAX_DLL_EXPORTS_DEFAULT))
                    if max_dll_exports <= 0:
                        max_dll_exports = MAX_DLL_EXPORTS_DEFAULT
                    dll_exports_num = min(len(available_exports), max_dll_exports)

                    if use_export_name:
                        function = available_exports[:dll_exports_num]
                        run_multiple_functions = True
                    else:
                        function = f"#1-{dll_exports_num}"
                        run_ordinal_range = True

        # To get to this stage, the user has enabled `enable_multi`, and has either specified an ordinal
        # range or requested that we use available exports by ordinal number, up to a limit
        if run_ordinal_range:
            ret_list = []
            with contextlib.suppress(ValueError, AssertionError):
                start, end = (int(_.lstrip("#")) for _ in function.replace("..", "-").split("-", 1))
                assert start < end
                # if there are more exports than max_dll_exports we still want to run the last export
                if max_dll_exports and len(available_exports) > max_dll_exports:
                    end -= 1
                    args = f'"{path}",#{len(available_exports)}'
                    if arguments:
                        args += f" {arguments}"
                    ret_list.append(self.execute(rundll32, args, path))
                # if there are multiple functions launch them by their ordinal number in a for loop
                for i in range(start, end + 1, 1):
                    args = f'"{path}",#{i}'
                    if arguments:
                        args += f" {arguments}"
                    ret_list.append(self.execute(rundll32, args, path))

        # To get to this stage, the user has enabled `enable_multi`, and has either specified a list of function names
        # or requested that we use available exports by name, up to a limit
        elif run_multiple_functions:
            ret_list = []
            for function_name in function:
                args = f'"{path}"' if dllloader == "regsvcs.exe" else f'"{path}",{function_name}'
                if arguments:
                    args += f" {arguments}"

                ret_list.append(self.execute(rundll32, args, path))
            return ret_list

        # To get to this stage, the user has either:
        # - enabled `enable_multi`, did not provide a function, and does not want to use export names (default to #1)
        # - specified a single function, either by name or by ordinal number
        # - specified multiple functions, but did not enable `enable_multi`
        else:
            args = f'"{path}"' if dllloader == "regsvcs.exe" else f'"{path}",{function}'
            if arguments:
                args += f" {arguments}"

            return self.execute(rundll32, args, path)
