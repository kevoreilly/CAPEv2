# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil

try:
    import re2 as re
except ImportError:
    import re

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.exceptions import CuckooPackageError
from lib.common.parse_pe import is_pe_image
from lib.common.zip_utils import extract_archive, extract_zip, get_file_names, get_infos

log = logging.getLogger(__name__)

EXE_REGEX = re.compile(
    r"(\.exe|\.dll|\.scr|\.msi|\.bat|\.lnk|\.js|\.jse|\.vbs|\.vbe|\.wsf|\.ps1|\.db|\.cmd|\.dat|\.tmp|\.temp)$", flags=re.IGNORECASE
)
PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]


class Zip(Package):
    """Zip analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
        ("SystemRoot", "system32", "wscript.exe"),
        ("SystemRoot", "system32", "rundll32.exe"),
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("ProgramFiles", "7-Zip", "7z.exe"),
        ("SystemRoot", "system32", "xpsrchvw.exe"),
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]

    def execute_interesting_file(self, root: str, file_name: str, file_path: str):
        log.debug('Interesting file_name: "%s"', file_name)
        if file_name.lower().endswith((".lnk", ".bat", ".cmd")):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = f'/c "cd ^"{root}^" && start /wait ^"^" ^"{file_path}^"'
            return self.execute(cmd_path, cmd_args, file_path)
        elif file_name.lower().endswith(".msi"):
            msi_path = self.get_path("msiexec.exe")
            msi_args = f'/I "{file_path}"'
            return self.execute(msi_path, msi_args, file_path)
        elif file_name.lower().endswith((".js", ".jse", ".vbs", ".vbe", ".wsf")):
            cmd_path = self.get_path("cmd.exe")
            wscript = self.get_path_app_in_path("wscript.exe")
            cmd_args = f'/c "cd ^"{root}^" && {wscript} ^"{file_path}^"'
            return self.execute(cmd_path, cmd_args, file_path)
        elif file_name.lower().endswith((".dll", ".db", ".dat", ".tmp", ".temp")):
            # We are seeing techniques where dll files are named with the .db/.dat/.tmp/.temp extensions
            if not file_name.lower().endswith(".dll"):
                with open(file_path, "rb") as f:
                    if not any(PE_indicator in f.read() for PE_indicator in PE_INDICATORS):
                        return
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
        elif file_name.lower().endswith(".ps1"):
            powershell = self.get_path_app_in_path("powershell.exe")
            args = f'-NoProfile -ExecutionPolicy bypass -File "{file_path}"'
            return self.execute(powershell, args, file_path)
        elif file_name.lower().endswith(".doc"):
            # Try getting winword or wordview as a backup
            try:
                word = self.get_path_glob("WINWORD.EXE")
            except CuckooPackageError:
                word = self.get_path_glob("WORDVIEW.EXE")

            return self.execute(word, f'"{file_path}" /q', file_path)
        elif is_pe_image(file_path):
            file_path = check_file_extension(file_path, ".exe")
            return self.execute(file_path, self.options.get("arguments"), file_path)
        else:
            cmd_path = self.get_path("cmd.exe")
            cmd_args = f'/c "cd ^"{root}^" && start /wait ^"^" ^"{file_path}^"'
            return self.execute(cmd_path, cmd_args, file_path)

    def start(self, path):
        password = self.options.get("password", "infected")
        appdata = self.options.get("appdata")
        root = os.environ["APPDATA"] if appdata else os.environ["TEMP"]
        file_names = []
        try:
            zipinfos = get_infos(path)
            extract_zip(path, root, password, 0)
            for f in zipinfos:
                file_names.append(f.filename)
        except CuckooPackageError as e:
            # We should not be trying to do other things if we cannot extract the initial
            # password-protected zip file
            if "Bad password for file" in repr(e):
                raise

            # use 7z on files that Python zip module couldn't handle
            seven_zip_path = self.get_path_app_in_path("7z.exe")
            file_names = get_file_names(seven_zip_path, path)
            if len(file_names):
                extract_archive(seven_zip_path, path, root, password)

        # If the .zip only contains a 7zip file, then do:
        if len(file_names) == 1 and file_names[0].endswith(".7z"):
            seven_zip_path = self.get_path_app_in_path("7z.exe")
            nested_7z = os.path.join(root, file_names[0])
            file_names = get_file_names(seven_zip_path, nested_7z)
            if len(file_names):
                extract_archive(seven_zip_path, nested_7z, root, password)

        file_name = self.options.get("file")
        # If no file name is provided via option, discover files to execute.
        if not file_name:
            # No name provided try to find a better name.
            if not len(file_names):
                raise CuckooPackageError("Empty ZIP archive")

            # Attempt to find at least one valid exe extension in the archive
            interesting_files = []
            ret_list = []

            for f in file_names:
                if re.search(EXE_REGEX, f):
                    interesting_files.append(f)

            if not interesting_files:
                log.debug("No interesting files found, auto executing the first file: %s", file_names[0])
                interesting_files.append(file_names[0])

            log.debug("Missing file option, auto executing: %s", interesting_files)
            for interesting_file in interesting_files:
                file_path = os.path.join(root, interesting_file)
                ret_list.append(self.execute_interesting_file(root, interesting_file, file_path))

            return ret_list
        else:
            file_path = os.path.join(root, file_name)
            return self.execute_interesting_file(root, file_name, file_path)
