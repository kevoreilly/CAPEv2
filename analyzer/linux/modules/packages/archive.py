import logging
import os
import shutil
import tempfile
import subprocess

from lib.common.abstracts import Package
from lib.common.constants import (
    ARCHIVE_OPTIONS,
    OPT_ARGUMENTS,
    OPT_FILE,
    OPT_MULTI_PASSWORD,
    OPT_PASSWORD,
    OPT_RECURSION_DEPTH,
    OPT_MAX_EXECUTABLES,
)
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import (
    attempt_multiple_passwords,
    extract_archive,
    upload_extracted_files,
)

log = logging.getLogger(__name__)


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
        ("usr", "bin", "sh")
    ]
    summary = "Looks for executables inside an archive."
    description = f"""Uses 7z to unpack the archive with the supplied '{OPT_PASSWORD}' option.
    The default password is 'infected.'
    If the '{OPT_MULTI_PASSWORD}' option is set, the '{OPT_PASSWORD}' option can contain
    several possible passwords, colon-separated.
    If the '{OPT_FILE}' option was given, expect a file of that name to be in the archive,
    and attempt to execute it. Else, attempt to execute all executables in the archive.
    For each execution attempt, choose the appropriate method based on the file extension.
    Various options apply depending on the file type.
    The option '{OPT_ARGUMENTS}' will be applied to a .DLL or a PE executable.
    For recursive extraction guest Windows VM must contain die app (Detect It Easy) with extra
    database in Program Files.
    """
    option_names = sorted(set(ARCHIVE_OPTIONS + (OPT_MULTI_PASSWORD,)))

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
        try:
            seven_zip_path = self.get_path_app_in_path("7z")
        except CuckooPackageError:
            seven_zip_path = self.get_path_app_in_path("7zz")
        password = self.options.get(OPT_PASSWORD) or "infected"
        recursion_depth = max(0, int(self.options.get(OPT_RECURSION_DEPTH, 0) or 0))
        file_util_path = self.get_path_app_in_path("file") if recursion_depth > 0 else None

        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
        extract_archive(seven_zip_path, path, root, password, try_multiple_passwords)

        extracted_files = set()
        extracted_archives = set()
        for _ in range(recursion_depth):

            packs = []
            target_words = {'archive', 'compress', 'image', 'filesystem'}

            for r, _, files in os.walk(root):

                for file in files:
                    file_path = os.path.join(r, file)
                    if file_path in extracted_files:
                        continue

                    extracted_files.add(file_path)

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
                        for word in target_words:
                            if word in file_info:
                                packs.append(file_path)
                                break
                    except subprocess.CalledProcessError:
                        continue

            if packs:
                for p in packs:
                    output_dir = tempfile.mkdtemp(prefix="nested-", dir=root)

                    try:
                        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                        extract_archive(seven_zip_path, p, output_dir, password, try_multiple_passwords)
                        extracted_archives.add(p)
                    except Exception as e:
                        shutil.rmtree(output_dir, ignore_errors=True)
                        log.warning("Extraction failed for %s: %s", p, e)
            else:
                break

        # Discover actual extracted paths, including password-protected members.
        log.debug("Extracted archives:%s", extracted_archives)
        resolved_root = os.path.realpath(root)
        files_at_root = [
            os.path.relpath(p, root)
            for r, _, files in os.walk(root)
            for f in files
            if (p := os.path.join(r, f)) not in extracted_archives
            and os.path.commonpath((resolved_root, os.path.realpath(p))) == resolved_root
        ]
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
            file_path = os.path.join(root, file_name)
            pid = self.execute_interesting_file(root, file_name, file_path)
            return [pid] if pid is not None else []
