# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import glob
import importlib
import inspect
import logging
import os
import shutil

from lib.api.process import Process
from lib.common.common import check_file_extension, disable_wow64_redirection
from lib.common.exceptions import CuckooPackageError
from lib.common.parse_pe import choose_dll_export, is_pe_image
from lib.core.compound import create_custom_folders

# from typing import Dict, Any


log = logging.getLogger(__name__)

PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]


class Package:
    """Base abstract analysis package."""

    PATHS = []
    default_curdir = None

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.pids = []
        # Fetch the current working directory, defaults to $TEMP.

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def start(self, target: str):
        """Run analysis package.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        return True

    def configure(self, target: str):
        """Do package-specific configuration.

        Analysis packages can implement this method to perform pre-analysis
        configuration in the execution environment. This method will be called
        after the auxiliary modules are started but before the package start
        method is called.

        See the "configure_from_data" method for an alternative approach to
        package-specific configuration that lets configuration be treated as
        runtime data separate from the analysis package.
        """
        raise NotImplementedError

    def configure_from_data(self, target: str):
        """Do private package-specific configuration.

        Analysis packages can implement this method to perform pre-analysis
        configuration based on runtime data contained in "data/packages/<package_name>".

        This method raises:
         - ImportError when any exception occurs during import
         - AttributeError if the module configure function is invalid.
         - ModuleNotFoundError if the module does not support configuration from data
        """
        package_module_name = self.__class__.__module__.split(".")[-1]
        module_name = f"data.packages.{package_module_name}"
        try:
            m = importlib.import_module(module_name)
        except Exception as e:
            raise ImportError(f"error importing {module_name}: {e}") from e

        spec = inspect.getfullargspec(m.configure)
        if len(spec.args) != 2:
            err_msg = f"{module_name}.configure: expected 2 arguments, got {len(spec.args)}"
            raise AttributeError(err_msg)
        m.configure(self, target)

    def get_paths(self):
        """Get the default list of paths."""
        return self.PATHS

    def enum_paths(self):
        """Enumerate available paths."""
        for path in self.get_paths():
            basedir = path[0]
            sys32 = len(path) > 1 and path[1].lower() == "system32"
            if basedir == "SystemRoot":
                if not sys32 or "PE32+" not in self.config.file_type:
                    yield os.path.join(os.getenv("SystemRoot"), *path[1:])
                yield os.path.join(os.getenv("SystemRoot"), "sysnative", *path[2:])
            elif basedir == "ProgramFiles":
                if os.getenv("ProgramFiles(x86)"):
                    yield os.path.join(os.getenv("ProgramFiles(x86)"), *path[1:])
                yield os.path.join(os.getenv("ProgramFiles").replace(" (x86)", ""), *path[1:])
            elif basedir == "HomeDrive":
                # os.path.join() does not work well when giving just C:
                # instead of C:\\, so we manually add the backslash.
                homedrive = "{}\\".format(os.getenv("HomeDrive"))
                yield os.path.join(homedrive, *path[1:])
            elif os.getenv(basedir):
                yield os.path.join(os.getenv(basedir), *path[1:])
            else:
                yield os.path.join(*path)

    def get_path(self, application):
        """Search for the application in all available paths.
        @param application: application executable name
        @return: executable path
        """
        for path in self.enum_paths():
            if application in path and os.path.isfile(path):
                return path

        raise CuckooPackageError(f"Unable to find any {application} executable")

    def get_path_glob(self, application):
        """Search for the application in all available paths with glob support.
        @param application: application executable name
        @return: executable path
        """
        for path in self.enum_paths():
            for path in glob.iglob(path):
                if os.path.isfile(path) and (not application or application.lower() in path.lower()):
                    return path

        raise CuckooPackageError(f"Unable to find any {application} executable")

    def get_path_app_in_path(self, application):
        """Search for the application in all available paths.
        @param application: application executable name
        @return: executable path
        """
        for path in self.enum_paths():
            if os.path.isfile(path) and (not application or application.lower() in path.lower()):
                return path

        raise CuckooPackageError(f"Unable to find any {application} executable")

    def execute(self, path, args, interest):
        """Starts an executable for analysis.
        @param path: executable path
        @param args: executable arguments
        @param interest: file of interest, passed to the cuckoomon config
        @return: process pid
        """
        free = self.options.get("free", False)
        suspended = not free

        kernel_analysis = bool(self.options.get("kernel_analysis", False))

        p = Process(options=self.options, config=self.config)
        if not p.execute(path=path, args=args, suspended=suspended, kernel_analysis=kernel_analysis):
            raise CuckooPackageError("Unable to execute the initial process, analysis aborted")

        if free:
            return None

        if not kernel_analysis:
            p.inject(interest)

        p.resume()
        p.close()

        return p.pid

    def package_files(self):
        """A list of files to upload to host.
        The list should be a list of tuples (<path on guest>, <name of file in package_files folder>).
        (package_files is a folder that will be created in analysis folder).
        """
        return []

    def finish(self):
        """Finish run.
        If configured, upload memory dumps of
        all running processes.
        """

        return True

    @disable_wow64_redirection
    def move_curdir(self, filepath):
        """Move a file to the current working directory so it can be executed
        from there.
        @param filepath: the file to be moved
        @return: the new filepath
        """
        if "curdir" in self.options:
            self.curdir = os.path.expandvars(self.options["curdir"])
        elif self.default_curdir:
            self.curdir = os.path.expandvars(self.default_curdir)
        else:
            self.curdir = os.getenv("TEMP")
        # Try to create the folders for the cases of the custom paths other than %TEMP%
        create_custom_folders(self.curdir)

        # in some cases it has problems to create folder IDK why
        if not os.path.exists(self.curdir):
            return filepath

        newpath = os.path.join(self.curdir, os.path.basename(filepath))
        shutil.move(filepath, newpath)
        return newpath

    def execute_interesting_file(self, root: str, file_name: str, file_path: str):
        """
        Based on file extension or file contents, run relevant analysis package
        """
        # File extensions that require cmd.exe to run
        if file_name.lower().endswith((".lnk", ".bat", ".cmd")):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = f'/c "cd ^"{root}^" && start /wait ^"^" ^"{file_path}^"'
            return self.execute(cmd_path, cmd_args, file_path)
        # File extensions that require msiexec.exe to run
        elif file_name.lower().endswith(".msi"):
            msi_path = self.get_path("msiexec.exe")
            msi_args = f'/I "{file_path}"'
            return self.execute(msi_path, msi_args, file_path)
        # File extensions that require wscript.exe to run
        elif file_name.lower().endswith((".js", ".jse", ".vbs", ".vbe", ".wsf")):
            cmd_path = self.get_path("cmd.exe")
            wscript = self.get_path_app_in_path("wscript.exe")
            cmd_args = f'/c "cd ^"{root}^" && {wscript} ^"{file_path}^"'
            return self.execute(cmd_path, cmd_args, file_path)
        # File extensions that require rundll32.exe/regsvr32.exe to run
        elif file_name.lower().endswith((".dll", ".db", ".dat", ".tmp", ".temp")):
            # We are seeing techniques where dll files are named with the .db/.dat/.tmp/.temp extensions
            if not file_name.lower().endswith(".dll"):
                # Let's confirm that at least this is a PE
                with open(file_path, "rb") as f:
                    if not any(PE_indicator in f.read() for PE_indicator in PE_INDICATORS):
                        return
            dll_export = choose_dll_export(file_path)
            if dll_export == "DllRegisterServer":
                rundll32 = self.get_path("regsvr32.exe")
            else:
                rundll32 = self.get_path_app_in_path("rundll32.exe")
                function = self.options.get("function", "#1")
            arguments = self.options.get("arguments")
            dllloader = self.options.get("dllloader")
            dll_args = f'"{file_path}",{function}'
            if arguments:
                dll_args += f" {arguments}"
            if dllloader:
                newname = os.path.join(os.path.dirname(rundll32), dllloader)
                shutil.copy(rundll32, newname)
                rundll32 = newname
            return self.execute(rundll32, dll_args, file_path)
        # File extensions that require powershell.exe to run
        elif file_name.lower().endswith(".ps1"):
            powershell = self.get_path_app_in_path("powershell.exe")
            args = f'-NoProfile -ExecutionPolicy bypass -File "{file_path}"'
            return self.execute(powershell, args, file_path)
        # File extensions that require winword.exe/wordview.exe to run
        elif file_name.lower().endswith(".doc"):
            # Try getting winword or wordview as a backup
            try:
                word = self.get_path_glob("WINWORD.EXE")
            except CuckooPackageError:
                word = self.get_path_glob("WORDVIEW.EXE")
            return self.execute(word, f'"{file_path}" /q', file_path)
        # File extensions that require excel.exe to run
        elif file_name.lower().endswith(".xls"):
            # Try getting excel
            excel = self.get_path_glob("EXCEL.EXE")
            return self.execute(excel, f'"{file_path}" /q', file_path)
        # File extensions that require iexplore.exe to run
        elif file_name.lower().endswith(".html"):
            edge = self.get_path("msedge.exe")
            return self.execute(edge, f'"{file_path}"', file_path)
        # File extensions that are portable executables
        elif is_pe_image(file_path):
            file_path = check_file_extension(file_path, ".exe")
            return self.execute(file_path, self.options.get("arguments"), file_path)
        # Last ditch effort to attempt to execute this file
        else:
            # From zip_compound package
            if "." not in os.path.basename(file_path):
                new_path = f"{file_path}.exe"
                os.rename(file_path, new_path)
                file_path = new_path
            cmd_path = self.get_path("cmd.exe")
            cmd_args = f'/c "cd ^"{root}^" && start /wait ^"^" ^"{file_path}^"'
            return self.execute(cmd_path, cmd_args, file_path)


class Auxiliary:
    # Setting all Auxiliary to have a default priority of 0
    start_priority = 0
    stop_priority = 0

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.options = options
        self.config = config

    def add_pid(self, pid):
        pass

    def del_pid(self, pid):
        pass
