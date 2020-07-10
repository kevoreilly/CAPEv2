# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import shutil
import logging
import re

try:
    from rarfile import RarFile, BadRarFile

    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)


class Rar(Package):
    """Rar analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

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
            new_rar_path = rar_path + ".old"
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
                    raise CuckooPackageError("Unable to extract Rar file: " "{0}".format(e))
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
            raise CuckooPackageError("rarfile Python module not installed in guest.")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()
        if ext != ".rar":
            new_path = path + ".rar"
            os.rename(path, new_path)
            path = new_path

        root = os.environ["TEMP"]
        password = self.options.get("password")
        exe_regex = re.compile("(\.exe|\.scr|\.msi|\.bat|\.lnk)$", flags=re.IGNORECASE)

        rarinfos = self.get_infos(path)
        self.extract_rar(path, root, password)

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(rarinfos):
                # Attempt to find a valid exe extension in the archive
                for f in rarinfos:
                    if exe_regex.search(f.filename):
                        file_name = f.filename
                        break
                # Default to the first one if none found
                file_name = file_name if file_name else rarinfos[0].filename
                log.debug("Missing file option, auto executing: {0}".format(file_name))
            else:
                raise CuckooPackageError("Empty RAR archive")

        file_path = os.path.join(root, file_name)
        if file_name.lower().endswith(".lnk"):
            cmd_path = self.get_path("cmd.exe")
            cmd_args = '/c start /wait "" "{0}"'.format(file_path)
            return self.execute(cmd_path, cmd_args, file_path)
        else:
            return self.execute(file_path, self.options.get("arguments"), file_path)
