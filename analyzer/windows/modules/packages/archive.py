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


FILE_NAME_REGEX = re.compile("[\s]{2}((?:[a-zA-Z0-9\.\-,_\\\\]+( [a-zA-Z0-9\.\-,_\\\\]+)?)+)\\r")
EXE_REGEX = re.compile(r"(\.exe|\.dll|\.scr|\.msi|\.bat|\.lnk|\.js|\.jse|\.vbs|\.vbe|\.wsf|\.ps1|\.db|\.cmd|\.dat)$", flags=re.IGNORECASE)
PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]


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

    def extract_archive(self, seven_zip_path, archive_path, extract_path, password="infected"):
        """Extracts a nested archive file.
        @param seven_zip_path: path to 7z binary
        @param archive_path: archive path
        @param extract_path: where to extract
        @param password: archive password
        """
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

    def get_file_names(self, seven_zip_path, archive_path):
        """Get the file names from archive file.
        @param seven_zip_path: path to 7z binary
        @param archive_path: archive file path
        @return: A list of file names
        """
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

    def execute_interesting_file(self, root: str, file_name: str, file_path: str):
        log.debug('file_name: "%s"', file_name)
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
        elif file_name.lower().endswith((".db", ".dll", ".dat")):
            # We are seeing techniques where dll files are named with the .db/.dat extension
            if file_name.lower().endswith((".db", ".dat")):
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
        else:
            file_path = check_file_extension(file_path, ".exe")
            return self.execute(file_path, self.options.get("arguments"), file_path)

    def start(self, path):
        # Is 7z in analyzer/windows/bin?
        seven_zip_path = os.path.join(os.getcwd(), "bin", "7z.exe")
        if not os.path.exists(seven_zip_path):
            # Let's hope it's in the VM image
            seven_zip_path = self.get_path("7z.exe")

        password = self.options.get("password", "")

        archive_name = path.split("\\")[-1].split(".")[0]
        root = os.path.join(os.environ["TEMP"], archive_name)

        # Check if root exists already due to the file path
        if os.path.exists(root) and os.path.isfile(root):
            root = os.path.join(os.environ["TEMP"], "extracted_iso", archive_name)

        os.makedirs(root)

        file_names = self.get_file_names(seven_zip_path, path)
        if not len(file_names):
            raise CuckooPackageError("Empty archive")

        log.debug(file_names)
        self.extract_archive(seven_zip_path, path, root, password)

        # Handle special characters that 7ZIP cannot
        # We have the file names according to 7ZIP output (file_names)
        # We have the file names that were actually extracted (files at root)
        # If these values are different, replace all
        files_at_root = [os.path.join(r, f).replace(f"{root}\\", "") for r, _, files in os.walk(root) for f in files]
        log.debug(files_at_root)
        if set(file_names) != set(files_at_root):
            log.debug(f"Replacing {file_names} with {files_at_root}")
            file_names = files_at_root

        file_name = self.options.get("file")
        # If no file name is provided via option, discover files to execute.
        if not file_name:
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
