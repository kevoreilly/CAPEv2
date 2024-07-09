# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
from zipfile import BadZipfile, ZipFile

try:
    import re2 as re
except ImportError:
    import re

from lib.common.abstracts import Package
from lib.common.constants import (
    ARCHIVE_OPTIONS,
    DLL_OPTIONS,
    OPT_ARGUMENTS,
    OPT_DLLLOADER,
    OPT_FILE,
    OPT_FUNCTION,
    OPT_INJECTION,
    OPT_PASSWORD,
    OPT_PROCDUMP,
    OPT_UNPACKER,
)
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)


class Unpacker_zip(Package):
    """CAPE Unpacker zip analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]
    summary = "Unzip a file with the supplied password, execute its contents."
    description = f"""Extract the sample from a zip file. If the file name is not
    supplied in the '{OPT_FILE}" option, the first file in the zip is taken.
    Set options '{OPT_UNPACKER}=1', '{OPT_PROCDUMP}=0' and '{OPT_INJECTION}=0'.
    The execution method is chosen based on the filename extension."""
    option_names = sorted(set(ARCHIVE_OPTIONS + DLL_OPTIONS))

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.pids = []
        self.options[OPT_UNPACKER] = "1"
        self.options[OPT_PROCDUMP] = "0"
        self.options[OPT_INJECTION] = "0"

    def extract_zip(self, zip_path, extract_path, password, recursion_depth):
        """Extracts a nested ZIP file.
        @param zip_path: ZIP path
        @param extract_path: where to extract
        @param password: ZIP password
        @param recursion_depth: how deep we are in a nested archive
        """
        # Test if zip file contains a file named as itself.
        if self.is_overwritten(zip_path):
            log.debug("ZIP file contains a file with the same name, original is going to be overwritten")
            # TODO: add random string.
            new_zip_path = f"{zip_path}.old"
            shutil.move(zip_path, new_zip_path)
            zip_path = new_zip_path

        # Unpacker.
        with ZipFile(zip_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file") from e
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError(f"Unable to extract Zip file: {e}") from e
            finally:
                if recursion_depth < 4:
                    # Extract nested archives.
                    for name in archive.namelist():
                        if name.endswith(".zip"):
                            # Recurse.
                            try:
                                self.extract_zip(os.path.join(extract_path, name), extract_path, password, recursion_depth + 1)
                            except BadZipfile:
                                log.warning(
                                    "Nested zip file '%s' name end with 'zip' extension is not a valid zip, skipping extraction",
                                    name,
                                )
                            except RuntimeError as run_err:
                                log.error("Error to extract nested zip file %s with details: %s", name, run_err)

    def is_overwritten(self, zip_path):
        """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
        @param zip_path: zip file path
        @return: comparison boolean
        """
        with ZipFile(zip_path, "r") as archive:
            # Test if zip file contains a file named as itself.
            try:
                return any(name == os.path.basename(zip_path) for name in archive.namelist())
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file") from e

    def get_infos(self, zip_path):
        """Get information from ZIP file.
        @param zip_path: zip file path
        @return: ZipInfo class
        """
        try:
            with ZipFile(zip_path, "r") as archive:
                return archive.infolist()
        except BadZipfile as e:
            raise CuckooPackageError("Invalid Zip file") from e

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get(OPT_PASSWORD)
        exe_regex = re.compile(r"(\.exe|\.scr|\.msi|\.bat|\.lnk|\.js|\.jse|\.vbs|\.vbe|\.wsf\.ps1)$", flags=re.IGNORECASE)
        dll_regex = re.compile(r"(\.dll|\.ocx)$", flags=re.IGNORECASE)
        zipinfos = self.get_infos(path)
        self.extract_zip(path, root, password, 0)

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, take the first file.
        if file_name is None:
            # No name provided try to find a better name.
            if not len(zipinfos):
                raise CuckooPackageError("Empty ZIP archive")

            # Attempt to find a valid exe extension in the archive
            for f in zipinfos:
                if exe_regex.search(f.filename):
                    file_name = f.filename
                    break
            if file_name is None:
                for f in zipinfos:
                    if dll_regex.search(f.filename):
                        file_name = f.filename
                        break
            # Default to the first one if none found
            file_name = file_name or zipinfos[0].filename
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
        elif file_name.lower().endswith((".dll", ".ocx")):
            rundll32 = self.get_path_app_in_path("rundll32.exe")
            function = self.options.get(OPT_FUNCTION, "#1")
            arguments = self.options.get(OPT_ARGUMENTS)
            dllloader = self.options.get(OPT_DLLLOADER)
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
        return self.execute(file_path, self.options.get(OPT_ARGUMENTS), file_path)
