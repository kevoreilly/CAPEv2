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
    OPT_APPDATA,
    OPT_ARGUMENTS,
    OPT_CURDIR,
    OPT_DLLLOADER,
    OPT_EXTRACTOR,
    OPT_FILE,
    OPT_FREE,
    OPT_FUNCTION,
    OPT_JSON_CONFIG,
    OPT_MAX_EXECUTABLES,
    OPT_MULTI_PASSWORD,
    OPT_PASSWORD,
    OPT_RECURSION_DEPTH,
)
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import (
    NON_RECURSIVE_CONTAINER_EXTENSIONS,
    attempt_multiple_passwords,
    extract_archive,
    extract_compressed_stream,
    extract_rar_with_rarfile,
    extract_tar,
    extract_zip,
    get_interesting_files,
    is_probable_archive,
    is_rar_file,
    is_tar_or_compressed,
    is_within_root,
    is_wrong_password_error,
    is_zip_file,
    upload_extracted_files,
    winrar_extractor,
)
from lib.core.compound import create_custom_folders, extract_json_data
from modules.packages.dll import DLL_OPTIONS

log = logging.getLogger(__name__)

_MAX_ROOT_COPY_FILES = 100
_MAX_ROOT_COPY_BYTES = 100 * 1024 * 1024
_DEFAULT_JSON_CONFIG = "__configuration.json"
_SUPPORTED_EXTRACTORS = ("auto", "7z", "winrar", "zipfile", "tarfile", "rarfile")


def _option_enabled(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "on", "yes", "true")


def _normalize_relpath(path_value: str) -> str:
    return os.path.normpath(path_value.replace("\\", os.sep).replace("/", os.sep)).lower()


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
    summary = "Unpacks an archive (ZIP, RAR, 7z, ISO, TAR, etc.) and executes its contents."
    description = f"""Extracts archive contents using the selected '{OPT_EXTRACTOR}' backend
    (default 'auto': 7z.exe -> WinRAR.exe -> Python zipfile/tarfile -> rarfile) with the
    supplied '{OPT_PASSWORD}' option (default 'infected').
    Setting '{OPT_EXTRACTOR}' to a specific backend ('7z', 'winrar', 'zipfile', 'tarfile',
    or 'rarfile') disables automatic fallback.
    If '{OPT_MULTI_PASSWORD}' is set, '{OPT_PASSWORD}' may contain colon-separated passwords.
    If '{OPT_CURDIR}' is set, extracts into that directory; else if '{OPT_APPDATA}' is set,
    extracts into APPDATA; otherwise extracts to C:\\<archive_name>.
    If '{_DEFAULT_JSON_CONFIG}' (or '{OPT_JSON_CONFIG}') is present in the archive root,
    applies 'path_to_extract' moves and executes 'target_file' automatically.
    If '{OPT_FILE}' is given, executes that member; otherwise auto-executes executables up
    to '{OPT_MAX_EXECUTABLES}' (default 16).
    The options '{OPT_FUNCTION}' and '{OPT_DLLLOADER}' apply to .DLL execution attempts.
    The option '{OPT_ARGUMENTS}' applies to .DLL and PE executables.
    Set '{OPT_RECURSION_DEPTH}' for nested archive extraction (uses diec.exe if installed,
    falling back to built-in magic/extension detection).
    """
    option_names = sorted(
        set(DLL_OPTIONS + ARCHIVE_OPTIONS + (OPT_APPDATA, OPT_CURDIR, OPT_JSON_CONFIG, OPT_MULTI_PASSWORD))
    )

    def execute(self, path, args, interest):
        pid = super().execute(path, args, interest)
        if self.options.get(OPT_FREE, False):
            self._free_mode_execution_succeeded = True
            self._free_mode_iter_succeeded = True
        return pid

    def execute_files(self, root, interesting_files, max_executables=None, resolved_paths=None):
        ret_list = []
        last_error = None
        self._free_mode_execution_succeeded = False
        self._free_mode_iter_succeeded = False
        launched_files = 0
        resolved_paths = resolved_paths or {}
        try:
            for interesting_file in interesting_files:
                if max_executables is not None and launched_files >= max_executables:
                    log.info(
                        "Reached max_executables limit (%d) while auto-executing archive members",
                        max_executables,
                    )
                    break
                file_path = resolved_paths.get(interesting_file) or os.path.join(root, interesting_file)
                self._free_mode_iter_succeeded = False
                try:
                    pids = self.execute_interesting_file(root, interesting_file, file_path)
                    if pids:
                        launched_files += 1
                        if isinstance(pids, list):
                            ret_list.extend(pids)
                        else:
                            ret_list.append(pids)
                    elif self.options.get(OPT_FREE, False) and self._free_mode_iter_succeeded:
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
            self._free_mode_iter_succeeded = False

    def _try_get_app(self, application: str):
        try:
            return self.get_path_app_in_path(application)
        except CuckooPackageError:
            return None

    def _run_single_extractor(self, backend: str, archive_path: str, dest_dir: str, password: str, try_multiple: bool):
        if backend == "7z":
            seven_zip_path = self.get_path_app_in_path("7z.exe")
            extract_archive(seven_zip_path, archive_path, dest_dir, password, try_multiple)
            return

        if backend == "winrar":
            winrar_path = self.get_path_app_in_path("WinRAR.exe")
            if not winrar_path or not os.path.exists(winrar_path):
                raise CuckooPackageError("Unable to find any WinRAR.exe executable")
            winrar_extractor(winrar_path, dest_dir, archive_path, password, try_multiple)
            return

        if backend == "zipfile":
            extract_zip(
                archive_path,
                dest_dir,
                password,
                recursion_depth=0,
                try_multiple_passwords=try_multiple,
                recursive=False,
            )
            return

        if backend == "tarfile":
            try:
                extract_tar(archive_path, dest_dir)
            except CuckooPackageError as tar_err:
                try:
                    extract_compressed_stream(archive_path, dest_dir)
                except CuckooPackageError:
                    raise tar_err
            return

        if backend == "rarfile":
            extract_rar_with_rarfile(archive_path, dest_dir, password, try_multiple)
            return

        raise CuckooPackageError(
            f"Unsupported extractor '{backend}'. Supported values: {', '.join(_SUPPORTED_EXTRACTORS)}"
        )

    def _extract_with_backend(
        self,
        archive_path: str,
        dest_dir: str,
        password: str,
        try_multiple: bool,
        extractor: str,
    ):
        os.makedirs(dest_dir, exist_ok=True)

        if extractor != "auto":
            self._run_single_extractor(extractor, archive_path, dest_dir, password, try_multiple)
            return

        primary_error = None
        attempted = False

        # 1. 7-Zip (broadest archive/image support)
        seven_zip_path = self._try_get_app("7z.exe")
        if seven_zip_path:
            attempted = True
            try:
                extract_archive(seven_zip_path, archive_path, dest_dir, password, try_multiple)
                if os.listdir(dest_dir):
                    return
            except CuckooPackageError as err:
                if is_wrong_password_error(err):
                    raise
                primary_error = err

        # 2. WinRAR fallback (e.g., when 7z is absent or fails on some .iso/.rar files)
        winrar_path = self._try_get_app("WinRAR.exe")
        if winrar_path and os.path.exists(winrar_path):
            attempted = True
            try:
                winrar_extractor(winrar_path, dest_dir, archive_path, password, try_multiple)
                if os.listdir(dest_dir):
                    return
            except CuckooPackageError as err:
                if is_wrong_password_error(err):
                    raise
                if primary_error is None:
                    primary_error = err

        # 3. Python stdlib zipfile fallback
        if is_zip_file(archive_path):
            attempted = True
            try:
                extract_zip(
                    archive_path,
                    dest_dir,
                    password,
                    recursion_depth=0,
                    try_multiple_passwords=try_multiple,
                    recursive=False,
                )
                if os.listdir(dest_dir):
                    return
            except CuckooPackageError as err:
                if is_wrong_password_error(err):
                    raise
                if primary_error is None:
                    primary_error = err

        # 4. Python stdlib tarfile / single-file gzip/bz2/xz fallback
        if is_tar_or_compressed(archive_path):
            attempted = True
            try:
                self._run_single_extractor("tarfile", archive_path, dest_dir, password, try_multiple)
                if os.listdir(dest_dir):
                    return
            except CuckooPackageError as err:
                if primary_error is None:
                    primary_error = err

        # 5. Optional Python rarfile fallback
        if is_rar_file(archive_path):
            attempted = True
            try:
                extract_rar_with_rarfile(archive_path, dest_dir, password, try_multiple)
                if os.listdir(dest_dir):
                    return
            except CuckooPackageError as err:
                if is_wrong_password_error(err):
                    raise
                if primary_error is None:
                    primary_error = err

        if not os.listdir(dest_dir):
            if primary_error is not None:
                raise primary_error
            if not attempted:
                raise CuckooPackageError(
                    "Unable to extract archive: install 7-Zip or WinRAR in the guest for this archive format"
                )

    def _is_nested_archive(self, file_path: str, diec_path) -> bool:
        if os.path.islink(file_path):
            return False
        if os.path.basename(file_path).lower().endswith(NON_RECURSIVE_CONTAINER_EXTENSIONS):
            return False

        if diec_path:
            target_words = ("archive", "compress", "image", "filesystem", "zip", "rar", "sfx")
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
                return any(word in file_info for word in target_words)
            except (subprocess.CalledProcessError, OSError):
                return False

        return is_probable_archive(file_path)

    def _discover_extracted_files(self, root: str, extracted_archives: set) -> list:
        resolved_root = os.path.realpath(root)
        return [
            os.path.relpath(p, root)
            for r, _, files in os.walk(root)
            for f in files
            if (p := os.path.join(r, f)) not in extracted_archives
            and is_within_root(resolved_root, p)
            and os.path.isfile(os.path.realpath(p))
        ]

    def _resolve_target_member(self, root: str, file_name: str, file_names: list) -> str:
        """Resolve OPT_FILE directly in root or inside nested-* extracted subdirectories."""
        resolved_root = os.path.realpath(root)
        direct_path = os.path.join(root, file_name)
        if not is_within_root(resolved_root, direct_path):
            return file_name
        if os.path.exists(direct_path):
            return file_name

        norm_target = _normalize_relpath(file_name)
        for candidate in file_names:
            norm_candidate = _normalize_relpath(candidate)
            if norm_candidate == norm_target:
                return candidate
            parts = [p for p in norm_candidate.split(os.sep) if p not in ("", ".")]
            while parts and parts[0].startswith("nested-"):
                parts = parts[1:]
            if parts and os.sep.join(parts) == norm_target:
                return candidate

        return file_name

    def _move_staged_tree(self, staging_root: str, target_root: str):
        for item in os.listdir(staging_root):
            src = os.path.join(staging_root, item)
            dst = os.path.join(target_root, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
                shutil.rmtree(src, ignore_errors=True)
            else:
                if os.path.exists(dst) and os.path.isdir(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                shutil.move(src, dst)

    def _apply_compound_config(self, root: str, json_filename: str, file_names: list):
        """Apply __configuration.json moves and resolve target file if present."""
        resolved_root = os.path.realpath(root)
        json_path = os.path.join(root, json_filename)
        if not is_within_root(resolved_root, json_path):
            raise CuckooPackageError(f"JSON configuration '{json_filename}' is outside the extraction directory")

        raw_json = extract_json_data(root, json_filename)
        if not raw_json:
            return None, None, False
        if not isinstance(raw_json, dict):
            raise CuckooPackageError(f"Invalid JSON configuration in '{json_filename}': expected JSON object")

        json_dst_flds = raw_json.get("path_to_extract", {})
        if json_dst_flds is None:
            json_dst_flds = {}
        if not isinstance(json_dst_flds, dict):
            raise CuckooPackageError(f"Invalid 'path_to_extract' in '{json_filename}': expected JSON object")

        json_target = raw_json.get("target_file", "")
        if json_target is None:
            json_target = ""
        if not isinstance(json_target, str):
            raise CuckooPackageError(f"Invalid 'target_file' in '{json_filename}': expected string")

        explicit_file = self.options.get(OPT_FILE)
        target_file = explicit_file or json_target

        # Exclude configuration manifest from auto-execution candidates.
        norm_json = _normalize_relpath(json_filename)
        file_names[:] = [f for f in file_names if _normalize_relpath(f) != norm_json]

        target_srcdir, target_name = os.path.split(target_file) if target_file else ("", "")
        fin_target_path = os.path.join(root, target_file) if target_file else None
        norm_target = _normalize_relpath(target_file) if target_file else ""
        moved_any = False
        moved_prefixes = []

        # Move files that are specified in JSON file
        for src_rel, dst_fld in json_dst_flds.items():
            if not isinstance(src_rel, str) or not isinstance(dst_fld, str):
                raise CuckooPackageError(
                    f"Invalid 'path_to_extract' mapping in '{json_filename}': expected string keys and values"
                )
            oldpath = os.path.join(root, src_rel)
            if not is_within_root(resolved_root, oldpath):
                log.warning("Skipping path_to_extract entry '%s' outside extraction root", src_rel)
                continue
            resolved_old = os.path.realpath(oldpath)
            if resolved_old == resolved_root:
                log.warning("Skipping path_to_extract entry '%s' targeting extraction root itself", src_rel)
                continue
            if not os.path.exists(oldpath):
                log.warning("path_to_extract source '%s' not found in extracted archive", src_rel)
                continue

            dst_fld = os.path.expandvars(dst_fld)
            create_custom_folders(dst_fld)
            # If a relative path is provided, take only the basename
            clean_rel = src_rel.rstrip("\\/")
            fname = os.path.split(clean_rel)[1]
            newpath = os.path.join(dst_fld, fname)

            if resolved_old != os.path.realpath(newpath):
                # We cannot just shutil.move src dirs if src name == dst name.
                if os.path.isdir(oldpath):
                    log.debug("Resolved Dir: %s for folder '%s'", dst_fld, fname)
                    shutil.copytree(oldpath, newpath, dirs_exist_ok=True)
                    shutil.rmtree(oldpath)
                else:
                    log.debug("Resolved Dir: %s for file '%s'", dst_fld, fname)
                    shutil.move(oldpath, newpath)
                moved_any = True
                moved_prefixes.append(_normalize_relpath(clean_rel))

            if norm_target and norm_target == _normalize_relpath(src_rel):
                fin_target_path = newpath
                self.options[OPT_CURDIR] = dst_fld
                log.debug("New curdir value: %s", self.options[OPT_CURDIR])

        if moved_prefixes:
            file_names[:] = [
                f
                for f in file_names
                if not any(
                    (norm_f := _normalize_relpath(f)) == prefix or norm_f.startswith(prefix + os.sep)
                    for prefix in moved_prefixes
                )
            ]

        # Only runs if a relative path is given for target file
        # Errors out if the file's containing folder is shifted
        # before shifting the target file first.
        if target_file and target_srcdir and not os.path.exists(fin_target_path):
            raise CuckooPackageError(
                "Error getting the correct path for the target file! "
                "Target file should be moved before moving its containing source folder"
            )

        if target_file:
            log.debug("Final target name: %s", target_name)
            log.info("Final target path: %s", fin_target_path)
            return target_name, fin_target_path, moved_any

        return None, None, moved_any

    def start(self, path):
        extractor = (self.options.get(OPT_EXTRACTOR) or "auto").strip().lower()
        if extractor not in _SUPPORTED_EXTRACTORS:
            raise CuckooPackageError(
                f"Unsupported extractor '{extractor}'. Supported values: {', '.join(_SUPPORTED_EXTRACTORS)}"
            )

        password = self.options.get(OPT_PASSWORD) or "infected"
        archive_name = Path(path).name
        has_explicit_recursion = OPT_RECURSION_DEPTH in self.options and self.options.get(OPT_RECURSION_DEPTH) not in (
            None,
            "",
        )
        recursion_depth = max(0, int(self.options.get(OPT_RECURSION_DEPTH, 0) or 0))
        diec_path = self._try_get_app("diec.exe") if recursion_depth > 0 else None

        curdir_opt = self.options.get(OPT_CURDIR)
        appdata_opt = _option_enabled(self.options.get(OPT_APPDATA))
        use_staging = False

        if curdir_opt:
            target_root = os.path.expandvars(curdir_opt)
            create_custom_folders(target_root)
            use_staging = True
        elif appdata_opt:
            target_root = os.environ["APPDATA"]
            create_custom_folders(target_root)
            use_staging = True
        else:
            # We are extracting the archive to C:\\<archive_name> rather than the TEMP directory because
            # actors are using LNK files that use relative directory traversal at arbitrary depth.
            # They expect to find the root of the drive.
            target_root = os.path.join("C:\\", archive_name)

            # Check if root exists already due to the file path
            if os.path.exists(target_root) and os.path.isfile(target_root):
                target_root = os.path.join("C:\\", "extracted_iso", archive_name)

            os.makedirs(target_root, exist_ok=True)

        staging_dir = tempfile.mkdtemp(prefix="cape-archive-") if use_staging else None
        extract_root = staging_dir or target_root

        try:
            try_multiple_passwords = attempt_multiple_passwords(self.options, password)
            self._extract_with_backend(path, extract_root, password, try_multiple_passwords, extractor)

            resolved_extract_root = os.path.realpath(extract_root)
            nested_dirs = set()
            extracted_files = set()
            extracted_archives = set()

            if recursion_depth > 0:
                for _ in range(recursion_depth):
                    packs = []
                    for r, _, files in os.walk(extract_root):
                        for file in files:
                            file_path = os.path.join(r, file)
                            if file_path in extracted_files:
                                continue

                            extracted_files.add(file_path)
                            if os.path.islink(file_path) or not is_within_root(resolved_extract_root, file_path):
                                continue
                            if self._is_nested_archive(file_path, diec_path):
                                packs.append(file_path)

                    if packs:
                        for p in packs:
                            output_dir = tempfile.mkdtemp(prefix="nested-", dir=extract_root)
                            nested_dirs.add(output_dir)

                            try:
                                try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                                self._extract_with_backend(
                                    p, output_dir, password, try_multiple_passwords, extractor
                                )
                                extracted_archives.add(p)
                            except Exception as e:
                                nested_dirs.discard(output_dir)
                                shutil.rmtree(output_dir, ignore_errors=True)
                                log.warning("Extraction failed for %s: %s", p, e)
                    else:
                        break
            elif not has_explicit_recursion:
                # Preserve legacy zip.py convenience: unwrap a single-member nested archive (1 level).
                initial_files = self._discover_extracted_files(extract_root, extracted_archives)
                if len(initial_files) == 1:
                    nested_archive = os.path.join(extract_root, initial_files[0])
                    if (
                        not os.path.islink(nested_archive)
                        and is_within_root(resolved_extract_root, nested_archive)
                        and is_probable_archive(nested_archive)
                    ):
                        output_dir = tempfile.mkdtemp(prefix="nested-", dir=extract_root)
                        nested_dirs.add(output_dir)
                        try:
                            try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                            self._extract_with_backend(
                                nested_archive, output_dir, password, try_multiple_passwords, extractor
                            )
                            if os.listdir(output_dir):
                                extracted_archives.add(nested_archive)
                            else:
                                nested_dirs.discard(output_dir)
                                shutil.rmtree(output_dir, ignore_errors=True)
                        except Exception as e:
                            nested_dirs.discard(output_dir)
                            shutil.rmtree(output_dir, ignore_errors=True)
                            log.warning("Single-member nested archive extraction failed for %s: %s", nested_archive, e)

            # Handle special characters that 7ZIP cannot
            # We have the file names according to 7ZIP output (file_names)
            # We have the file names that were actually extracted (files at root)
            # If these values are different, replace all
            log.debug("Extracted archives:%s", extracted_archives)
            files_at_root = self._discover_extracted_files(extract_root, extracted_archives)
            log.debug(files_at_root)

            if not files_at_root:
                raise CuckooPackageError("Empty archive")

            upload_extracted_files(extract_root, files_at_root)

            if use_staging:
                self._move_staged_tree(extract_root, target_root)
        finally:
            if staging_dir and os.path.exists(staging_dir):
                shutil.rmtree(staging_dir, ignore_errors=True)

        root = target_root
        file_names = list(files_at_root)

        # Auto-detect __configuration.json (or explicit json_config option)
        json_config_opt = self.options.get(OPT_JSON_CONFIG)
        json_filename = json_config_opt or _DEFAULT_JSON_CONFIG
        resolved_root = os.path.realpath(root)
        json_candidate = os.path.join(root, json_filename)
        if not is_within_root(resolved_root, json_candidate):
            raise CuckooPackageError(f"JSON configuration '{json_filename}' is outside the extraction directory")
        compound_target_name = None
        compound_target_path = None
        compound_moved = False
        if os.path.isfile(json_candidate):
            compound_target_name, compound_target_path, compound_moved = self._apply_compound_config(
                root, json_filename, file_names
            )
        elif json_config_opt:
            log.warning("JSON Config File '%s' not found inside archive", json_filename)

        if not use_staging and not compound_moved:
            total_bytes = 0
            if len(file_names) <= _MAX_ROOT_COPY_FILES:
                for rel_path in file_names:
                    try:
                        total_bytes += os.path.getsize(os.path.join(root, rel_path))
                    except OSError:
                        continue
                    if total_bytes > _MAX_ROOT_COPY_BYTES:
                        break

            # Copy these files to the root directory, just in case!
            if len(file_names) <= _MAX_ROOT_COPY_FILES and total_bytes <= _MAX_ROOT_COPY_BYTES:
                dirs = []
                for item in os.listdir(root):
                    d = os.path.join(root, item)
                    if not is_within_root(resolved_root, d):
                        continue
                    if d in nested_dirs or d in extracted_archives:
                        continue
                    if _normalize_relpath(item) == _normalize_relpath(json_filename):
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
                    len(file_names),
                    total_bytes,
                )

        if compound_target_name and compound_target_path:
            return self.execute_files(
                root,
                [compound_target_name],
                resolved_paths={compound_target_name: compound_target_path},
            )

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, discover files to execute.
        if not file_name:
            if not file_names:
                raise CuckooPackageError("Empty archive")
            # Attempt to find at least one valid exe extension in the archive
            interesting_files = get_interesting_files(file_names)

            if not interesting_files:
                log.debug("No interesting files found, auto executing the first file: %s", file_names[0])
                interesting_files.append(file_names[0])

            max_executables = max(1, int(self.options.get(OPT_MAX_EXECUTABLES, 16) or 16))
            log.debug("Missing file option, auto executing: %s", interesting_files)
            return self.execute_files(root, interesting_files, max_executables=max_executables)
        else:
            resolved_member = self._resolve_target_member(root, file_name, file_names)
            return self.execute_files(root, [resolved_member])
