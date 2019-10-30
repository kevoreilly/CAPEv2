# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import logging

try:
    import re2 as re
except ImportError:
    import re

from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)

class ZipBatch(Package):
    """Zip batch analysis package."""
    PATHS = [
             ("SystemRoot", "system32", "cmd.exe"),
             ("SystemRoot", "system32", "wscript.exe"),
             ("SystemRoot", "system32", "rundll32.exe"),
             ("SystemRoot", "sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
             ("SystemRoot", "system32", "xpsrchvw.exe"),
            ]
    def extract_zip(self, zip_path, extract_path, password, recursion_depth):
        """Extracts a nested ZIP file.
        @param zip_path: ZIP path
        @param extract_path: where to extract
        @param password: ZIP password
        @param recursion_depth: how deep we are in a nested archive
        """
        # Test if zip file contains a file named as itself.
        if self.is_overwritten(zip_path):
            log.debug("ZIP file contains a file with the same name, original is going to be overwrite")
            # TODO: add random string.
            new_zip_path = zip_path + ".old"
            shutil.move(zip_path, new_zip_path)
            zip_path = new_zip_path

        # Extraction.
        with ZipFile(zip_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file: "
                                             "{0}".format(e))
            finally:
                if recursion_depth < 4:
                    # Extract nested archives.
                    for name in archive.namelist():
                        if name.endswith(".zip"):
                            # Recurse.
                            try:
                                self.extract_zip(os.path.join(extract_path, name), extract_path, password, recursion_depth + 1)
                            except BadZipfile:
                                log.warning("Nested zip file '%s' name end with 'zip' extension is not a valid zip. Skip extracting" % name)
                            except RuntimeError as run_err:
                                log.error("Error to extract nested zip file %s with details: %s" % name, run_err)

    def is_overwritten(self, zip_path):
        """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
        @param zip_path: zip file path
        @return: comparison boolean
        """
        with ZipFile(zip_path, "r") as archive:
            try:
                # Test if zip file contains a file named as itself.
                for name in archive.namelist():
                    if name == os.path.basename(zip_path):
                        return True
                return False
            except BadZipfile:
                raise CuckooPackageError("Invalid Zip file")

    def get_infos(self, zip_path):
        """Get information from ZIP file.
        @param zip_path: zip file path
        @return: ZipInfo class
        """
        try:
            with ZipFile(zip_path, "r") as archive:
                return archive.infolist()
        except BadZipfile:
            raise CuckooPackageError("Invalid Zip file")

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password")
        exe_regex = re.compile('(\.exe|\.scr|\.msi|\.bat|\.lnk|\.js|\.jse|\.vbs|\.vbe|\.wsf)$',flags=re.IGNORECASE)
        dll_regex = re.compile('(\.dll|\.ocx)$',flags=re.IGNORECASE)
        zipinfos = self.get_infos(path)
        self.extract_zip(path, root, password, 0)

        file_name = self.options.get("file")
        # If no file name is provided via option, take the first file.
        if not file_name:
            # No name provided try to find a better name.
            if len(zipinfos):
                # Attempt to find a valid exe extension in the archive
                for f in zipinfos:
                    file_name = f.filename
                    file_path = os.path.join(root, file_name)
                    log.debug("file_name: \"%s\"" % (file_name))
                    if file_name.lower().endswith(".lnk"):
                        cmd_path = self.get_path("cmd.exe")
                        cmd_args = "/c start /wait \"\" \"{0}\"".format(file_path)
                        try:
                            self.execute(cmd_path, cmd_args, file_path)
                        except:
                            pass
                    elif file_name.lower().endswith(".msi"):
                        msi_path = self.get_path("msiexec.exe")
                        msi_args = "/I \"{0}\"".format(file_path)
                        try:
                            self.execute(msi_path, msi_args, file_path)
                        except:
                            pass
                    elif file_name.lower().endswith((".js", ".jse", ".vbs", ".vbe", ".wsf")):
                        wscript = self.get_path_app_in_path("wscript.exe")
                        wscript_args = "\"{0}\"".format(file_path)
                        try:
                            self.execute(wscript, wscript_args, file_path)
                        except:
                            pass
                    elif file_name.lower().endswith((".dll", ".ocx")):
                        rundll32 = self.get_path_app_in_path("rundll32.exe")
                        function = self.options.get("function", "#1")
                        arguments = self.options.get("arguments")
                        dllloader = self.options.get("dllloader")
                        dll_args = "\"{0}\",{1}".format(file_path, function)
                        if arguments:
                            dll_args += " {0}".format(arguments)
                        if dllloader:
                            newname = os.path.join(os.path.dirname(rundll32), dllloader)
                            shutil.copy(rundll32, newname)
                            rundll32 = newname
                        try:
                            self.execute(rundll32, dll_args, file_path)
                        except:
                            pass
                    elif file_name.lower().endswith(".ps1"):
                        powershell = self.get_path_app_in_path("powershell.exe")
                        args = "-NoProfile -ExecutionPolicy bypass -File \"{0}\"".format(path)
                        try:
                            self.execute(powershell, args, file_path)
                        except:
                            pass
                    else:
                        try:
                            self.execute(file_path, self.options.get("arguments"), file_path)
                        except:
                            pass
            else:
                raise CuckooPackageError("Empty ZIP archive")
