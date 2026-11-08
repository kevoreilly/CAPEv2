# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from lib.common.abstracts import Package
from lib.common.constants import (
    ARCHIVE_OPTIONS,
    OPT_ARGUMENTS,
    OPT_DLLLOADER,
    OPT_FILE,
    OPT_FREE,
    OPT_FUNCTION,
    OPT_MULTI_PASSWORD,
    OPT_PASSWORD,
    OPT_RECURSION_DEPTH,
    OPT_MAX_EXECUTABLES,
)
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import (
    attempt_multiple_passwords,
    extract_archive,
    get_interesting_files,
    upload_extracted_files,
    winrar_extractor,
)
from modules.packages.dll import DLL_OPTIONS

log = logging.getLogger(__name__)

_MAX_ROOT_COPY_FILES = 100
_MAX_ROOT_COPY_BYTES = 100 * 1024 * 1024


class Archive(Package):
    """Archive analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "msiexec.exe"),
        ("SystemRoot", "system32", "cmd.exe"),
        ("SystemRoot", "system32", "wscript.exe"),
        ("SystemRoot", "system32", "rundll32.exe"),
        ("SystemRoot", "system32", "regsvr32.exe"),
        ("SystemRoot", "sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("SystemRoot", "system32", "xpsrchvw.exe"),
        ("ProgramFiles", "7-Zip", "7z.exe"),
        ("ProgramFiles", "WinRAR", "WinRAR.exe"),
        ("ProgramFiles", "die", "diec.exe"),
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
    For recursive extraction guest Windows VM must contain die app (Detect It Easy) with extra
    database in Program Files.
    """
    option_names = sorted(set(DLL_OPTIONS + ARCHIVE_OPTIONS + (OPT_MULTI_PASSWORD,)))

    def execute(self, path, args, interest):
        pid = super().execute(path, args, interest)
        if self.options.get(OPT_FREE, False):
            self._free_mode_execution_succeeded = True
        return pid

    def execute_files(self, root, interesting_files, max_executables=None):
        ret_list = []
        last_error = None
        self._free_mode_execution_succeeded = False
        launched_files = 0
        try:
            for interesting_file in interesting_files:
                if max_executables is not None and launched_files >= max_executables:
                    log.info(
                        "Reached max_executables limit (%d) while auto-executing archive members",
                        max_executables,
                    )
                    break
                file_path = os.path.join(root, interesting_file)
                try:
                    pids = self.execute_interesting_file(root, interesting_file, file_path)
                    if pids:
                        launched_files += 1
                        if isinstance(pids, list):
                            ret_list.extend(pids)
                        else:
                            ret_list.append(pids)
                    elif self.options.get(OPT_FREE, False) and self._free_mode_execution_succeeded:
                        launched_files += 1
                except CuckooPackageError as e:
                    last_error = e
                    log.error("Failed to execute interesting file '%s': %s", interesting_file, e)

            if not ret_list:
                if self.options.get(OPT_FREE, False) and self._free_mode_execution_succeeded:
                    return ret_list
                if last_error:
                    raise last_error
                raise CuckooPackageError("Unable to execute any file from archive, analysis aborted")

            return ret_list
        finally:
            self._free_mode_execution_succeeded = False

    def start(self, path):
        # 7za and 7r is limited so better install it inside of the vm
        # seven_zip_path = os.path.join(os.getcwd(), "bin", "7z.exe")
        # if not os.path.exists(seven_zip_path):
        # Let's hope it's in the VM image
        seven_zip_path = self.get_path_app_in_path("7z.exe")
        password = self.options.get(OPT_PASSWORD) or "infected"
        archive_name = Path(path).name
        recursion_depth = max(0, int(self.options.get(OPT_RECURSION_DEPTH, 0) or 0))
        diec_path = self.get_path_app_in_path("diec.exe") if recursion_depth > 0 else None

        # We are extracting the archive to C:\\<archive_name> rather than the TEMP directory because
        # actors are using LNK files that use relative directory traversal at arbitrary depth.
        # They expect to find the root of the drive.
        root = os.path.join("C:\\", archive_name)

        # Check if root exists already due to the file path
        if os.path.exists(root) and os.path.isfile(root):
            root = os.path.join("C:\\", "extracted_iso", archive_name)

        os.makedirs(root, exist_ok=True)

        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
        seven_zip_error = None
        try:
            extract_archive(seven_zip_path, path, root, password, try_multiple_passwords)
        except CuckooPackageError as err:
            if "Wrong password" in str(err):
                raise
            seven_zip_error = err

        # Try extract with winrar, in some cases 7z-full fails with .Iso
        if seven_zip_error is not None or not os.listdir(root):
            try:
                winrar_path = self.get_path_app_in_path("WinRAR.exe")
            except CuckooPackageError:
                winrar_path = None
                if seven_zip_error is not None:
                    raise seven_zip_error
            if winrar_path and os.path.exists(winrar_path):
                winrar_extractor(winrar_path, root, path, password, try_multiple_passwords)
            elif seven_zip_error is not None:
                raise seven_zip_error

        nested_dirs = set()
        extracted_files = set()
        extracted_archives = set()
        for _ in range(recursion_depth):

            packs = []
            target_words = ("archive", "compress", "image", "filesystem", "zip", "rar", "sfx")

            for r, _, files in os.walk(root):

                for file in files:
                    file_path = os.path.join(r, file)
                    if file_path in extracted_files:
                        continue

                    extracted_files.add(file_path)

                    try:
                        result = subprocess.run(
                            [diec_path, "-p", file_path],
                            capture_output=True,
                            text=True,
                            check=True,
                            encoding="utf-8",
                            errors="replace",
                        )
                        file_info = result.stdout.replace(file_path, "").lower()
                        for word in target_words:
                            if word in file_info:
                                packs.append(file_path)
                                break
                    except subprocess.CalledProcessError:
                        continue

            if packs:
                for p in packs:
                    output_dir = tempfile.mkdtemp(prefix="nested-", dir=root)
                    nested_dirs.add(output_dir)

                    try:
                        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                        extract_archive(seven_zip_path, p, output_dir, password, try_multiple_passwords)
                        extracted_archives.add(p)
                    except Exception as e:
                        nested_dirs.discard(output_dir)
                        shutil.rmtree(output_dir, ignore_errors=True)
                        log.warning("Extraction failed for %s: %s", p, e)
            else:
                break

        # Handle special characters that 7ZIP cannot
        # We have the file names according to 7ZIP output (file_names)
        # We have the file names that were actually extracted (files at root)
        # If these values are different, replace all
        log.debug("Extracted archives:%s", extracted_archives)
        resolved_root = os.path.realpath(root)
        files_at_root = [
            os.path.relpath(p, root)
            for r, _, files in os.walk(root)
            for f in files
            if (p := os.path.join(r, f)) not in extracted_archives
            and os.path.commonpath((resolved_root, os.path.realpath(p))) == resolved_root
            and os.path.isfile(os.path.realpath(p))
        ]
        log.debug(files_at_root)
        file_names = files_at_root

        if not file_names:
            raise CuckooPackageError("Empty archive")

        upload_extracted_files(root, files_at_root)

        total_bytes = 0
        if len(files_at_root) <= _MAX_ROOT_COPY_FILES:
            for rel_path in files_at_root:
                try:
                    total_bytes += os.path.getsize(os.path.join(root, rel_path))
                except OSError:
                    continue
                if total_bytes > _MAX_ROOT_COPY_BYTES:
                    break

        # Copy these files to the root directory, just in case!
        if len(files_at_root) <= _MAX_ROOT_COPY_FILES and total_bytes <= _MAX_ROOT_COPY_BYTES:
            dirs = []
            for item in os.listdir(root):
                d = os.path.join(root, item)
                resolved_d = os.path.realpath(d)
                if os.path.commonpath((resolved_root, resolved_d)) != resolved_root:
                    continue
                if d in nested_dirs or d in extracted_archives:
                    continue
                if os.path.isdir(d):
                    if d not in dirs:
                        dirs.append(d)
                        try:
                            shutil.copytree(d, os.path.join("C:\\", item), dirs_exist_ok=True)
                        except Exception as e:
                            log.warning("Couldn't copy %s to root of C: %s", d, str(e))
                else:
                    try:
                        shutil.copy(d, "C:\\")
                    except Exception as e:
                        log.warning("Couldn't copy %s to root of C: %s", d, str(e))
        else:
            log.info(
                "Skipping copy of %d archive members (%d bytes) to C:\\",
                len(files_at_root),
                total_bytes,
            )

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, discover files to execute.
        if not file_name:
            # Attempt to find at least one valid exe extension in the archive
            interesting_files = get_interesting_files(file_names)

            if not interesting_files:
                log.debug("No interesting files found, auto executing the first file: %s", file_names[0])
                interesting_files.append(file_names[0])

            max_executables = max(1, int(self.options.get(OPT_MAX_EXECUTABLES, 16) or 16))
            log.debug("Missing file option, auto executing: %s", interesting_files)
            return self.execute_files(root, interesting_files, max_executables=max_executables)
        else:
            return self.execute_files(root, [file_name])
