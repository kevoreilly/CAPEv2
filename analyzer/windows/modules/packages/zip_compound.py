# Copyright (C) 2021 CSIT
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
from typing import Tuple

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.core.compound import create_custom_folders, extract_json_data

log = logging.getLogger(__name__)


class ZipCompound(Package):
    """Extended functionality from the zip package to process compound samples"""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
        ("SystemRoot", "system32", "wscript.exe"),
        ("SystemRoot", "system32", "rundll32.exe"),
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("SystemRoot", "system32", "xpsrchvw.exe"),
    ]

    @staticmethod
    def is_valid_extension(filename: str) -> bool:
        """
        Checks given filename for extensions that the zip_compound package can run.
        @param filename: name or full path of the file.
        @return: Boolean whether extension is recognised.
        """

        valid = (
            ".exe",
            ".dll",
            ".scr",
            ".msi",
            ".bat",
            ".lnk",
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".wsf",
            ".ps1",
        )
        return filename.endswith(valid)

    def process_unzipped_contents(self, unzipped_directory: str, json_filename: str) -> Tuple[str, str]:
        """Checks JSON to move the various files to."""
        raw_json = extract_json_data(unzipped_directory, json_filename)

        json_dst_flds = raw_json.get("path_to_extract", {})
        target_file = raw_json.get("target_file", "")

        # Enforce the requirement of having a specified file. No guessing.
        target_file = target_file or self.options.get("file")
        if not target_file:
            raise CuckooPackageError("File must be specified in the JSON or the web submission UI!")
        elif not self.is_valid_extension(target_file):
            raise CuckooPackageError("Invalid, unsupported or no extension recognised by zip_compound package")

        # In case the "file" submittion option is relative, we split here
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
                    self.options["curdir"] = dst_fld
                    log.debug("New curdir value: %s", self.options["curdir"])

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

    def prepare_zip_compound(self, path: str, json_filename: str) -> Tuple[str, str]:
        """Pre-process the submitted zip file"""
        password = self.options.get("password")
        if password is None:
            log.info("No archive password provided")
            password = b""

        if "curdir" in self.options:
            root = self.options["curdir"]
        elif "appdata" in self.options:
            root = os.environ["APPDATA"]
        else:
            root = os.environ["TEMP"]
        create_custom_folders(root)

        # Have to shift this import here because of how analyzer's Package.__subclasses__ work
        from modules.packages.zip import Zip

        z = Zip()
        z.extract_zip(path, root, password, 0)

        return self.process_unzipped_contents(root, json_filename)

    def start(self, path, json_config="__configuration.json"):
        file_name, file_path = self.prepare_zip_compound(path, json_config)
        file_name = file_name.lower()

        if file_name.endswith(".lnk"):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = f"/c start /wait '' '{file_path}'"
            return self.execute(cmd_path, cmd_args, file_path)
        elif file_name.endswith(".msi"):
            msi_path = self.get_path("msiexec.exe")
            msi_args = f"/I '{file_path}'"
            return self.execute(msi_path, msi_args, file_path)
        elif file_name.endswith((".js", ".jse", ".vbs", ".vbe", ".wsf")):
            wscript = self.get_path_app_in_path("wscript.exe")
            wscript_args = f"'{file_path}'"
            return self.execute(wscript, wscript_args, file_path)
        elif file_name.endswith(".dll"):
            rundll32 = self.get_path_app_in_path("rundll32.exe")
            function = self.options.get("function", "#1")
            arguments = self.options.get("arguments")
            dllloader = self.options.get("dllloader")
            dll_args = f"'{file_path}',{function}"
            if arguments:
                dll_args += f" {arguments}"
            if dllloader:
                newname = os.path.join(os.path.dirname(rundll32), dllloader)
                shutil.copy(rundll32, newname)
                rundll32 = newname
            return self.execute(rundll32, dll_args, file_path)
        elif file_name.endswith(".ps1"):
            powershell = self.get_path_app_in_path("powershell.exe")
            args = f"-NoProfile -ExecutionPolicy bypass -File '{path}'"
            return self.execute(powershell, args, file_path)
        else:
            if "." not in os.path.basename(file_path):
                new_path = f"{file_path}.exe"
                os.rename(file_path, new_path)
                file_path = new_path
            return self.execute(file_path, self.options.get("arguments"), file_path)
