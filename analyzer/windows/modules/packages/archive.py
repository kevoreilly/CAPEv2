# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
from pathlib import Path

from lib.common.abstracts import Package
from lib.common.constants import (
    ARCHIVE_OPTIONS,
    OPT_ARGUMENTS,
    OPT_DLLLOADER,
    OPT_FILE,
    OPT_FUNCTION,
    OPT_MULTI_PASSWORD,
    OPT_PASSWORD,
)
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import (
    attempt_multiple_passwords,
    extract_archive,
    get_file_names,
    get_interesting_files,
    upload_extracted_files,
    winrar_extractor,
)
from modules.packages.dll import DLL_OPTIONS

log = logging.getLogger(__name__)


class Archive(Package):
    """Archive analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
        ("SystemRoot", "system32", "wscript.exe"),
        ("SystemRoot", "system32", "rundll32.exe"),
        ("SystemRoot", "system32", "regsvr32.exe"),
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("SystemRoot", "system32", "xpsrchvw.exe"),
        ("ProgramFiles", "7-Zip", "7z.exe"),
        ("ProgramFiles", "WinRAR", "WinRAR.exe"),
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
    ]
    summary = "Looks for executables inside an archive."
    description = f"""Uses 7z.exe to unpack the archive with the supplied '{OPT_PASSWORD}' option.
    The default password is 'infected.'
    If the '{OPT_MULTI_PASSWORD}' option is set, the '{OPT_PASSWORD}' option can contain
    several possible passwords, colon-separated.
    If 7z.exe could not open the archive, try WinRAR.exe.
    If the '{OPT_FILE}' option was given, expect a file of that name to be in the archive,
    and attempt to execute it. Else, attempt to execute all executables in the archive.
    For each execution attempt, choose the appropriate method based on the file extension.
    Various options apply depending on the file type.
    The options '{OPT_FUNCTION}' and '{OPT_DLLLOADER}' will be applied to .DLL execution attempts.
    The option '{OPT_ARGUMENTS}' will be applied to a .DLL or a PE executable.
    """
    option_names = sorted(set(DLL_OPTIONS + ARCHIVE_OPTIONS + (OPT_MULTI_PASSWORD,)))

    def start(self, path):
        # 7za and 7r is limited so better install it inside of the vm
        # seven_zip_path = os.path.join(os.getcwd(), "bin", "7z.exe")
        # if not os.path.exists(seven_zip_path):
        # Let's hope it's in the VM image
        seven_zip_path = self.get_path_app_in_path("7z.exe")
        password = self.options.get(OPT_PASSWORD, "infected")
        archive_name = Path(path).name

        # We are extracting the archive to C:\\<archive_name> rather than the TEMP directory because
        # actors are using LNK files that use relative directory traversal at arbitrary depth.
        # They expect to find the root of the drive.
        root = os.path.join("C:\\", archive_name)

        # Check if root exists already due to the file path
        if os.path.exists(root) and os.path.isfile(root):
            root = os.path.join("C:\\", "extracted_iso", archive_name)

        os.makedirs(root, exist_ok=True)

        file_names = get_file_names(seven_zip_path, path)
        if len(file_names):
            try_multiple_passwords = attempt_multiple_passwords(self.options, password)
            extract_archive(seven_zip_path, path, root, password, try_multiple_passwords)

        # Try extract with winrar, in some cases 7z-full fails with .Iso
        if not file_names:
            winrar_path = self.get_path_app_in_path("WinRAR.exe")
            if os.path.exists(winrar_path):
                file_names = winrar_extractor(winrar_path, root, path)

        if not file_names:
            raise CuckooPackageError("Empty archive")

        # Handle special characters that 7ZIP cannot
        # We have the file names according to 7ZIP output (file_names)
        # We have the file names that were actually extracted (files at root)
        # If these values are different, replace all
        files_at_root = [os.path.join(r, f).replace(f"{root}\\", "") for r, _, files in os.walk(root) for f in files]
        log.debug(files_at_root)
        if set(file_names) != set(files_at_root):
            log.debug(f"Replacing {file_names} with {files_at_root}")
            file_names = files_at_root

        upload_extracted_files(root, files_at_root)

        # Copy these files to the root directory, just in case!
        dirs = []
        for item in os.listdir(root):
            d = os.path.join(root, item)
            if os.path.isdir(d):
                if d not in dirs:
                    dirs.append(d)
                    try:
                        shutil.copytree(d, os.path.join("C:\\", item))
                    except Exception as e:
                        log.warning(f"Couldn't copy {d} to root of C: {e}")
            else:
                try:
                    shutil.copy(d, "C:\\")
                except Exception as e:
                    log.warning(f"Couldn't copy {d} to root of C: {e}")

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, discover files to execute.
        if not file_name:
            ret_list = []

            # Attempt to find at least one valid exe extension in the archive
            interesting_files = get_interesting_files(file_names)

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
