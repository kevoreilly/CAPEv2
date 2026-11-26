import logging
import os
import shutil
import subprocess
import tempfile

from lib.common.abstracts import Package
from lib.common.constants import (
    ARCHIVE_OPTIONS,
    OPT_ARGUMENTS,
    OPT_EXTRACTOR,
    OPT_FILE,
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
    extract_tar,
    extract_zip,
    is_probable_archive,
    is_rar_file,
    is_tar_or_compressed,
    is_within_root,
    is_wrong_password_error,
    is_zip_file,
    unrar_extractor,
    upload_extracted_files,
)

log = logging.getLogger(__name__)

_SUPPORTED_EXTRACTORS = ("auto", "7z", "unrar", "zipfile", "tarfile")


class Archive(Package):
    """Archive analysis package."""

    PATHS = [
        ("usr", "bin", "node"),
        ("usr", "bin", "java"),
        ("usr", "bin", "dpkg"),
        ("usr", "bin", "perl"),
        ("usr", "bin", "python3"),
        ("usr", "bin", "pwsh"),
        ("usr", "bin", "7z"),
        ("usr", "bin", "7zz"),
        ("usr", "bin", "file"),
        ("usr", "bin", "unrar"),
        ("usr", "bin", "bash"),
        ("usr", "bin", "sh"),
    ]
    summary = "Unpacks an archive (ZIP, TAR, GZ, BZ2, XZ, 7z, RAR, ISO) and executes its contents."
    description = f"""Extracts archive contents using the selected '{OPT_EXTRACTOR}' backend
    (default 'auto': 7z/7zz -> unrar -> Python zipfile/tarfile) with the supplied
    '{OPT_PASSWORD}' option (default 'infected').
    Setting '{OPT_EXTRACTOR}' to a specific backend ('7z', 'unrar', 'zipfile', or 'tarfile')
    disables automatic fallback.
    If the '{OPT_MULTI_PASSWORD}' option is set, the '{OPT_PASSWORD}' option can contain
    several possible passwords, colon-separated.
    If the '{OPT_FILE}' option was given, expect a file of that name to be in the archive,
    and attempt to execute it. Else, attempt to execute all executables in the archive up
    to '{OPT_MAX_EXECUTABLES}' (default 16).
    The option '{OPT_ARGUMENTS}' will be applied to ELF executables.
    Set '{OPT_RECURSION_DEPTH}' for nested archive extraction (uses 'file' if installed,
    falling back to built-in magic/extension detection).
    """
    option_names = sorted(set(ARCHIVE_OPTIONS + (OPT_ARGUMENTS, OPT_MULTI_PASSWORD)))

    def _try_get_app(self, application: str):
        try:
            return self.get_path_app_in_path(application)
        except CuckooPackageError:
            return None

    def _find_seven_zip(self):
        return self._try_get_app("7z") or self._try_get_app("7zz")

    def _run_single_extractor(self, backend: str, archive_path: str, dest_dir: str, password: str, try_multiple: bool):
        if backend == "7z":
            seven_zip_path = self._find_seven_zip()
            if not seven_zip_path:
                raise CuckooPackageError("Unable to find any 7z or 7zz executable")
            extract_archive(seven_zip_path, archive_path, dest_dir, password, try_multiple)
            return

        if backend == "unrar":
            unrar_path = self.get_path_app_in_path("unrar")
            unrar_extractor(unrar_path, dest_dir, archive_path, password, try_multiple)
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
        os.makedirs(dest_dir, mode=0o700, exist_ok=True)

        if extractor != "auto":
            self._run_single_extractor(extractor, archive_path, dest_dir, password, try_multiple)
            return

        primary_error = None
        attempted = False

        # 1. 7z / 7zz (broadest archive/image support)
        seven_zip_path = self._find_seven_zip()
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

        # 2. unrar fallback for RAR archives
        if is_rar_file(archive_path):
            unrar_path = self._try_get_app("unrar")
            if unrar_path:
                attempted = True
                try:
                    unrar_extractor(unrar_path, dest_dir, archive_path, password, try_multiple)
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

        if not os.listdir(dest_dir):
            if primary_error is not None:
                raise primary_error
            if not attempted:
                raise CuckooPackageError(
                    "Unable to extract archive: install 7z/7zz or unrar in the guest for this archive format"
                )

    def _is_nested_archive(self, file_path: str, file_util_path) -> bool:
        if os.path.basename(file_path).lower().endswith(NON_RECURSIVE_CONTAINER_EXTENSIONS):
            return False

        if file_util_path:
            target_words = {"archive", "compress", "image", "filesystem"}
            try:
                result = subprocess.run(
                    [file_util_path, "--brief", file_path],
                    capture_output=True,
                    text=True,
                    check=True,
                    encoding="utf-8",
                    errors="replace",
                )
                file_info = result.stdout.lower()
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
            if (p := os.path.join(r, f)) not in extracted_archives and is_within_root(resolved_root, p)
        ]

    def _resolve_target_member(self, root: str, file_name: str, file_names: list) -> str:
        """Resolve OPT_FILE directly in root or inside nested-* extracted subdirectories."""
        resolved_root = os.path.realpath(root)
        direct_path = os.path.join(root, file_name)
        if not is_within_root(resolved_root, direct_path):
            return file_name
        if os.path.exists(direct_path):
            return file_name

        norm_target = os.path.normpath(file_name.replace("\\", "/"))
        for candidate in file_names:
            norm_candidate = os.path.normpath(candidate.replace("\\", "/"))
            if norm_candidate == norm_target:
                return candidate
            parts = [p for p in norm_candidate.split("/") if p not in ("", ".")]
            while parts and parts[0].startswith("nested-"):
                parts = parts[1:]
            if parts and "/".join(parts) == norm_target:
                return candidate

        return file_name

    def start(self, path):
        # Children may still need sibling members after start() returns.
        self._extraction_dir = tempfile.TemporaryDirectory(prefix="cape-archive-", dir=os.getenv("TEMP"))
        try:
            return self._start(path, self._extraction_dir.name)
        except Exception:
            self._extraction_dir.cleanup()
            raise

    def finish(self):
        try:
            return super().finish()
        finally:
            if hasattr(self, "_extraction_dir"):
                self._extraction_dir.cleanup()

    def _start(self, path, root):
        extractor = (self.options.get(OPT_EXTRACTOR) or "auto").strip().lower()
        if extractor not in _SUPPORTED_EXTRACTORS:
            raise CuckooPackageError(
                f"Unsupported extractor '{extractor}'. Supported values: {', '.join(_SUPPORTED_EXTRACTORS)}"
            )

        password = self.options.get(OPT_PASSWORD) or "infected"
        has_explicit_recursion = OPT_RECURSION_DEPTH in self.options and self.options.get(OPT_RECURSION_DEPTH) not in (
            None,
            "",
        )
        recursion_depth = max(0, int(self.options.get(OPT_RECURSION_DEPTH, 0) or 0))
        file_util_path = self._try_get_app("file") if recursion_depth > 0 else None

        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
        self._extract_with_backend(path, root, password, try_multiple_passwords, extractor)

        extracted_files = set()
        extracted_archives = set()
        if recursion_depth > 0:
            for _ in range(recursion_depth):
                packs = []
                for r, _, files in os.walk(root):
                    for file in files:
                        file_path = os.path.join(r, file)
                        if file_path in extracted_files:
                            continue

                        extracted_files.add(file_path)
                        if self._is_nested_archive(file_path, file_util_path):
                            packs.append(file_path)

                if packs:
                    for p in packs:
                        output_dir = tempfile.mkdtemp(prefix="nested-", dir=root)

                        try:
                            try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                            self._extract_with_backend(p, output_dir, password, try_multiple_passwords, extractor)
                            extracted_archives.add(p)
                        except Exception as e:
                            shutil.rmtree(output_dir, ignore_errors=True)
                            log.warning("Extraction failed for %s: %s", p, e)
                else:
                    break
        elif not has_explicit_recursion:
            initial_files = self._discover_extracted_files(root, extracted_archives)
            if len(initial_files) == 1:
                nested_archive = os.path.join(root, initial_files[0])
                if is_probable_archive(nested_archive):
                    output_dir = tempfile.mkdtemp(prefix="nested-", dir=root)
                    try:
                        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                        self._extract_with_backend(
                            nested_archive, output_dir, password, try_multiple_passwords, extractor
                        )
                        if os.listdir(output_dir):
                            extracted_archives.add(nested_archive)
                        else:
                            shutil.rmtree(output_dir, ignore_errors=True)
                    except Exception as e:
                        shutil.rmtree(output_dir, ignore_errors=True)
                        log.warning("Single-member nested archive extraction failed for %s: %s", nested_archive, e)

        # Discover actual extracted paths, including password-protected members.
        log.debug("Extracted archives:%s", extracted_archives)
        files_at_root = self._discover_extracted_files(root, extracted_archives)
        log.debug(files_at_root)
        file_names = files_at_root

        if not file_names:
            raise CuckooPackageError("Empty archive")

        upload_extracted_files(root, files_at_root)

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, discover files to execute.
        if not file_name:
            ret_list = []
            max_executables = max(1, int(self.options.get(OPT_MAX_EXECUTABLES, 16) or 16))

            # Let the dispatcher recognize extensions case-insensitively and ELF
            # contents independently of suffix, rather than filtering twice.
            log.debug("Missing file option, inspecting extracted members: %s", file_names)
            for interesting_file in file_names:
                if len(ret_list) >= max_executables:
                    log.info(
                        "Reached max_executables limit (%d) while auto-executing archive members",
                        max_executables,
                    )
                    break
                file_path = os.path.join(root, interesting_file)
                pid = self.execute_interesting_file(root, interesting_file, file_path)
                if pid is not None:
                    ret_list.append(pid)

            return ret_list
        else:
            resolved_member = self._resolve_target_member(root, file_name, file_names)
            file_path = os.path.join(root, resolved_member)
            pid = self.execute_interesting_file(root, resolved_member, file_path)
            return [pid] if pid is not None else []
