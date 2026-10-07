import logging
import os
import shutil
import subprocess
from pathlib import Path

from lib.common.abstracts import Package
from lib.common.constants import (
    ARCHIVE_OPTIONS,
    OPT_ARGUMENTS,
    OPT_FILE,
    OPT_MULTI_PASSWORD,
    OPT_PASSWORD,
    OPT_RECURSION_DEPTH,
)
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import (
    attempt_multiple_passwords,
    extract_archive,
    get_file_names,
    get_interesting_files,
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
        # seven_zip_path = os.path.join(os.getcwd(), "7z")
        # if not os.path.exists(seven_zip_path):
        # Let's hope it's in the VM image
        try:
            seven_zip_path = self.get_path_app_in_path("7z")
        except CuckooPackageError:
            seven_zip_path = self.get_path_app_in_path("7zz")
        password = self.options.get(OPT_PASSWORD, "infected")
        archive_name = Path(path).name
        recursion_depth = max(0, int(self.options.get(OPT_RECURSION_DEPTH, 0)))
        file_util_path = self.get_path_app_in_path("file") if recursion_depth > 0 else None

        # We are extracting the archive to /<archive_name> rather than the TEMP directory because
        # actors are using LNK files that use relative directory traversal at arbitrary depth.
        # They expect to find the root of the drive.
        root = os.path.join("/", archive_name)

        # Check if root exists already due to the file path
        if os.path.exists(root) and os.path.isfile(root):
            root = os.path.join("/", "extracted_iso", archive_name)

        os.makedirs(root, exist_ok=True)

        file_names = get_file_names(seven_zip_path, path)
        if len(file_names):
            try_multiple_passwords = attempt_multiple_passwords(self.options, password)
            extract_archive(seven_zip_path, path, root, password, try_multiple_passwords)

        if not file_names:
            raise CuckooPackageError("Empty archive")

        extracted_files = set()
        extracted_archives = set()
        for i in range(0, recursion_depth):

            packs = []
            target_words = {'archive', 'compress', 'image', 'filesystem'}

            for r, _, files in os.walk(root):

                for file in files:
                    file_path = os.path.join(r, file)
                    if file_path in extracted_files:
                        continue

                    extracted_files.add(file_path)

                    try:
                        result = subprocess.run([file_util_path, file_path], capture_output=True, text=True, check=True, encoding="utf-8")
                        file_info = result.stdout
                        for word in target_words:
                            if word in file_info:
                                packs.append(file_path)
                                break
                    except subprocess.CalledProcessError:
                        continue

            if packs:
                j = 0
                for p in packs:
                    pack_name = os.path.basename(p)
                    output_dir = os.path.join(root, str(i), str(j), pack_name)
                    os.makedirs(output_dir, exist_ok=True)

                    try:
                        try_multiple_passwords = attempt_multiple_passwords(self.options, password)
                        extract_archive(seven_zip_path, p, output_dir, password, try_multiple_passwords)
                        extracted_archives.add(p)
                    except Exception as e:
                        log.warning("Extraction failed for %s: %s", p, e)

                    j += 1
            else:
                break

        # Handle special characters that 7ZIP cannot
        # We have the file names according to 7ZIP output (file_names)
        # We have the file names that were actually extracted (files at root)
        # If these values are different, replace all
        log.debug("Extracted archives:%s", extracted_archives)
        files_at_root = [
            os.path.relpath(p, root)
            for r, _, files in os.walk(root)
            for f in files
            if (p := os.path.join(r, f)) not in extracted_archives
        ]
        log.debug(files_at_root)
        file_names = files_at_root

        upload_extracted_files(root, files_at_root)

        # Copy these files to the root directory, just in case!
        dirs = []
        for item in os.listdir(root):
            d = os.path.join(root, item)
            if os.path.isdir(d):
                if d not in dirs:
                    dirs.append(d)
                    try:
                        shutil.copytree(d, os.path.join("/", item))
                    except Exception as e:
                        log.warning("Couldn't copy %s to root %s", d, str(e))
            else:
                try:
                    shutil.copy(d, "/")
                except Exception as e:
                    log.warning("Couldn't copy %s to root %s", d, str(e))

        file_name = self.options.get(OPT_FILE)
        # If no file name is provided via option, discover files to execute.
        if not file_name:
            ret_list = []

            # Attempt to find at least one valid exe extension in the archive
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
