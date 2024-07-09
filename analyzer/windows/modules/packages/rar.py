# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil

try:
    from rarfile import BadRarFile, RarFile

    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import ARCHIVE_OPTIONS, DLL_OPTIONS, OPT_FILE, OPT_PASSWORD
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import get_interesting_files, upload_extracted_files

log = logging.getLogger(__name__)


class Rar(Package):
    """Rar analysis package."""

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
    summary = "Unpack a .rar archive with the given password and execute the contents appropriately."
    description = f"""Extract the contents of a .rar file. If the file name is not
    supplied in the '{OPT_FILE}" option, examine the archive for files that look executable.
    If none can be found, the first file in the archive is taken.
    If the archive contains .dll files, then options 'function', 'arguments' and 'dllloader' will take effect.
    The execution method is chosen based on the filename extension."""
    option_names = sorted(set(ARCHIVE_OPTIONS + DLL_OPTIONS))

    def extract_rar(self, rar_path, extract_path, password):
        """Extracts a nested RAR file.
        @param rar_path: RAR path
        @param extract_path: where to extract
        @param password: RAR password
        """
        # Test if rar file contains a file named as itself.
        if self.is_overwritten(rar_path):
            log.debug("RAR file contains a file with the same name, original is going to be overwrite")
            # TODO: add random string.
            new_rar_path = f"{rar_path}.old"
            shutil.move(rar_path, new_rar_path)
            rar_path = new_rar_path

        # Extraction.
        with RarFile(rar_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
            except BadRarFile:
                raise CuckooPackageError("Invalid Rar file")
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError(f"Unable to extract Rar file: {e}")
            finally:
                # Extract nested archives.
                for name in archive.namelist():
                    if name.endswith(".rar"):
                        # Recurse.
                        self.extract_rar(os.path.join(extract_path, name), extract_path, password)

    def is_overwritten(self, rar_path):
        """Checks if the RAR file contains another file with the same name, so it is going to be overwritten.
        @param rar_path: rar file path
        @return: comparison boolean
        """
        with RarFile(rar_path, "r") as archive:
            try:
                # Test if rar file contains a file named as itself.
                for name in archive.namelist():
                    if name == os.path.basename(rar_path):
                        return True
                return False
            except BadRarFile:
                raise CuckooPackageError("Invalid Rar file")

    def get_infos(self, rar_path):
        """Get information from RAR file.
        @param rar_path: rar file path
        @return: RarInfo class
        """
        try:
            with RarFile(rar_path, "r") as archive:
                return archive.infolist()
        except BadRarFile:
            raise CuckooPackageError("Invalid Rar file")

    def start(self, path):
        if not HAS_RARFILE:
            raise CuckooPackageError("rarfile Python module not installed in guest")

        # Check file extension.
        path = check_file_extension(path, ".rar")

        root = os.environ["TEMP"]
        password = self.options.get(OPT_PASSWORD)

        rarinfos = self.get_infos(path)
        self.extract_rar(path, root, password)

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, take the first file.
        if not file_name:
            # If no file names to choose from, bail
            if not len(rarinfos):
                raise CuckooPackageError("Empty RAR archive")

            file_names = [f.filename for f in rarinfos]

            upload_extracted_files(root, file_names)
            ret_list = []

            # Attempt to find a valid exe extension in the archive
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
