# Copyright (C) 2021 CSIT
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
from typing import Tuple

from lib.common.abstracts import Package
from lib.common.constants import DLL_OPTIONS, OPT_APPDATA, OPT_CURDIR, OPT_FILE, OPT_PASSWORD
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import extract_zip
from lib.core.compound import create_custom_folders, extract_json_data

log = logging.getLogger(__name__)


class ZipCompound(Package):
    """Extended functionality from the zip package to process compound samples"""

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
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft", "Edge", "Application", "msedge.exe"),
    ]
    summary = "Unpack a .zip archive with the given password and execute the contents appropriately."
    description = f"""Extract the contents of a .zip file.
    Supply '{OPT_PASSWORD}' if the .zip file is encrypted (defaults to blank).
    *NB*: Either '{OPT_FILE}' option must be set, or a '__configuration.json' file must be present in the zip file.
    Sample json file:

        {{
            "path_to_extract": {{
                "a.exe": "%USERPROFILE%\\Desktop\\a\\b\\c",
                "folder_b": "%appdata%"
            }},
            "target_file":"a.exe"
        }}

    If the '{OPT_CURDIR}' option is specified, use that as the current directory.
    Else, if the '{OPT_APPDATA}' option is specified, run the executable from the APPDATA directory.
    The execution method is chosen based on the filename extension.
    If executing a .dll file, then options 'function', 'arguments' and 'dllloader' will take effect.
    """
    option_names = sorted(set(DLL_OPTIONS + (OPT_CURDIR, OPT_FILE, OPT_PASSWORD, OPT_APPDATA)))

    def process_unzipped_contents(self, unzipped_directory: str, json_filename: str) -> Tuple[str, str]:
        """Checks JSON to move the various files to."""
        raw_json = extract_json_data(unzipped_directory, json_filename)

        json_dst_flds = raw_json.get("path_to_extract", {})
        target_file = raw_json.get("target_file", "")

        # Enforce the requirement of having a specified file. No guessing.
        target_file = target_file or self.options.get(OPT_FILE)
        if not target_file:
            raise CuckooPackageError("File must be specified in the JSON or the web submission UI!")

        # In case the "file" submission option is relative, we split here
        target_srcdir, target_name = os.path.split(target_file)

        # Note for 32bit samples: Even if JSON configutation specifies "System32",
        # wow64 redirection will still happen
        # Commented out since redirection-related issues should be uncommon.
        # if is_os_64bit():
        #     wow64 = c_ulong(0)
        #     KERNEL32.Wow64DisableWow64FsRedirection(byref(wow64))

        fin_target_path = os.path.join(unzipped_directory, target_file)

        # Move files that are specified in JSON file
        if json_dst_flds:
            for f, dst_fld in json_dst_flds.items():
                oldpath = os.path.join(unzipped_directory, f)
                dst_fld = os.path.expandvars(dst_fld)
                create_custom_folders(dst_fld)
                # If a relative path is provided, take only the basename
                fname = os.path.split(f)[1]
                newpath = os.path.join(dst_fld, fname)

                # We cannot just shutil.move src dirs if src name == dst name.
                if os.path.isdir(oldpath):
                    log.debug("Resolved Dir: %s for folder '%s'", dst_fld, fname)
                    shutil.copytree(oldpath, newpath, dirs_exist_ok=True)
                    shutil.rmtree(oldpath)
                else:
                    log.debug("Resolved Dir: %s for file '%s'", dst_fld, fname)
                    shutil.move(oldpath, newpath)

                if target_file.lower() == f.lower():
                    fin_target_path = newpath
                    self.options[OPT_CURDIR] = dst_fld
                    log.debug("New curdir value: %s", self.options[OPT_CURDIR])

        # Only runs if a relative path is given for target file
        # Errors out if the file's containing folder is shifted
        # before shifting the target file first.
        if target_srcdir and not os.path.exists(fin_target_path):
            raise CuckooPackageError(
                "Error getting the correct path for the target file! \
                Target file should be moved before moving its containing\
                source folder"
            )

        log.debug("Final target name: %s", target_name)
        log.info("Final target path: %s", fin_target_path)
        return target_name, fin_target_path

    def prepare_zip_compound(self, path: str, json_filename: str) -> Tuple[str, str, str]:
        """Pre-process the submitted zip file"""
        password = self.options.get(OPT_PASSWORD)
        if password is None:
            log.info("No archive password provided")
            password = b""

        if OPT_CURDIR in self.options:
            root = self.options[OPT_CURDIR]
        elif OPT_APPDATA in self.options:
            root = os.environ["APPDATA"]
        else:
            root = os.environ["TEMP"]
        create_custom_folders(root)

        extract_zip(path, root, password, 0)

        file_name, file_path = self.process_unzipped_contents(root, json_filename)
        return root, file_name, file_path

    def start(self, path, json_config="__configuration.json"):
        root, file_name, file_path = self.prepare_zip_compound(path, json_config)
        return self.execute_interesting_file(root, file_name, file_path)
