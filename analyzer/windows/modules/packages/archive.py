# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
import subprocess

try:
    import re2 as re
except ImportError:
    import re

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)


FILE_NAME_REGEX = re.compile("[\s]{2}([a-zA-Z0-9\.\-_\\\\]+)\\r")
EXE_REGEX = re.compile(r"(\.exe|\.dll|\.scr|\.msi|\.bat|\.lnk|\.js|\.jse|\.vbs|\.vbe|\.wsf|\.ps1)$", flags=re.IGNORECASE)


class Archive(Package):
    """Archive analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
        ("SystemRoot", "system32", "wscript.exe"),
        ("SystemRoot", "system32", "rundll32.exe"),
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("SystemRoot", "system32", "xpsrchvw.exe"),
        ("ProgramFiles", "7-Zip", "7z.exe"),
    ]

    def extract_archive(self, archive_path, extract_path, password="infected"):
        """Extracts a nested archive file.
        @param archive_path: archive path
        @param extract_path: where to extract
        @param password: archive password
        """
        seven_zip_path = self.get_path("7z.exe")
        log.debug([seven_zip_path, "x", "-p", "-y", f"-o{extract_path}", archive_path])
        p = subprocess.run([seven_zip_path, "x", "-p", "-y", f"-o{extract_path}", archive_path], capture_output=True)
        stdoutput, stderr = p.stdout, p.stderr
        log.debug(p.stdout + p.stderr)
        if b"Wrong password" in stderr:
            shutil.rmtree(extract_path, ignore_errors=True)
            p = subprocess.run([seven_zip_path, "x", f"-p{password}", "-y", f"-o{extract_path}", archive_path], capture_output=True)
            stdoutput, stderr = p.stdout, p.stderr
            log.debug(p.stdout + p.stderr)
            if b"Wrong password" in stderr:
                raise
        elif b"Can not open the file as archive" in stdoutput:
            raise TypeError

    def get_file_names(self, archive_path):
        """Get the file names from archive file.
        @param archive_path: archive file path
        @return: A list of file names
        """
        seven_zip_path = self.get_path("7z.exe")
        log.debug([seven_zip_path, "l", archive_path])
        p = subprocess.run([seven_zip_path, "l", archive_path], capture_output=True)
        stdoutput = p.stdout.decode()
        stdoutput_lines = stdoutput.split("\n")

        in_table = False
        items_under_header = False
        file_names = []
        for line in stdoutput_lines:
            if in_table:
                # This is a line in the table (header or footer separators)
                if "-----" in line:
                    if items_under_header:
                        items_under_header = False
                    else:
                        items_under_header = True
                    continue

                # These are the lines that we care about, since they contain the file names
                if items_under_header:
                    # Find the end of the line (\r), note the carriage return since 7zip will run on Windows
                    file_name = re.search(FILE_NAME_REGEX, line)
                    if file_name:
                        # The first capture group is the whole file name + returns
                        # The second capture group is just the file name
                        file_name = file_name.group(1)
                        file_names.append(file_name)
            else:
                # Table Headers
                if all(item.lower() in line.lower() for item in ["Date", "Time", "Attr", "Size", "Compressed", "Name"]):
                    in_table = True

        return file_names

    def start(self, path):
        password = self.options.get("password", "")

        archive_name = path.split("\\")[-1].split(".")[0]
        root = os.path.join(os.environ["TEMP"], archive_name)
        os.mkdir(root)

        file_names = self.get_file_names(path)
        if not len(file_names):
            raise CuckooPackageError("Empty archive")

        log.debug(file_names)
        self.extract_archive(path, root, password)
        log.debug([item for item in os.walk(root)])

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # Attempt to find a valid exe extension in the archive
            for f in file_names:
                log.debug(f)
                if re.search(EXE_REGEX, f):
                    log.debug("hit")
                    file_name = f
                    break
            # Default to the first one if none found
            file_name = file_name or file_names[0]
            log.debug("Missing file option, auto executing: %s", file_name)

        file_path = os.path.join(root, file_name)
        log.debug('file_name: "%s"', file_name)

        if file_name.lower().endswith(".lnk"):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = f'/c start /wait "" "{file_path}"'
            return self.execute(cmd_path, cmd_args, file_path)
        elif file_name.lower().endswith(".msi"):
            msi_path = self.get_path("msiexec.exe")
            msi_args = f'/I "{file_path}"'
            return self.execute(msi_path, msi_args, file_path)
        elif file_name.lower().endswith((".js", ".jse", ".vbs", ".vbe", ".wsf")):
            wscript = self.get_path_app_in_path("wscript.exe")
            wscript_args = f'"{file_path}"'
            return self.execute(wscript, wscript_args, file_path)
        elif file_name.lower().endswith(".dll"):
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
            args = f'-NoProfile -ExecutionPolicy bypass -File "{path}"'
            return self.execute(powershell, args, file_path)
        else:
            path = check_file_extension(path, ".exe")
            return self.execute(file_path, self.options.get("arguments"), file_path)
