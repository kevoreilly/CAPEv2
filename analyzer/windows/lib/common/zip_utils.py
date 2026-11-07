import hashlib
import logging
import os
import shutil
import subprocess
from pathlib import Path
from zipfile import BadZipfile, ZipFile

from lib.common.constants import OPT_MULTI_PASSWORD
from lib.common.exceptions import CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

FILE_EXT_OF_INTEREST = [
    ".bat",
    ".cmd",
    ".dat",
    ".db",
    ".dll",
    ".doc",
    ".exe",
    ".html",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".temp",
    ".tmp",
    ".vbe",
    ".vbs",
    ".wsf",
    ".xls",
]


def _cleanup_new_entries(extract_path, existing_entries):
    """Remove any file, symlink, or directory in extract_path not in existing_entries."""
    if not os.path.exists(extract_path):
        os.makedirs(extract_path, exist_ok=True)
        return
    for item in os.listdir(extract_path):
        if item not in existing_entries:
            target = os.path.join(extract_path, item)
            try:
                if os.path.islink(target) or os.path.isfile(target):
                    os.unlink(target)
                elif os.path.isdir(target):
                    shutil.rmtree(target, ignore_errors=True)
            except OSError as e:
                log.warning("Failed to clean up new entry %s: %s", target, e)


def extract_archive(seven_zip_path, archive_path, extract_path, password="infected", try_multiple_passwords=False):
    """Extracts a nested archive file.
    @param seven_zip_path: path to 7z binary
    @param archive_path: archive path
    @param extract_path: where to extract
    @param password: archive password
    @param try_multiple_passwords: we will be splitting the password on the ':' symbol,
        and trying each one to extract the archive
    """
    os.makedirs(extract_path, exist_ok=True)
    existing_entries = set(os.listdir(extract_path))
    password = password or "infected"
    passwords = ([p for p in password.split(":") if p] or ["infected"]) if try_multiple_passwords else [password]

    for candidate in passwords:
        log.debug([seven_zip_path, "x", f"-p{candidate}", "-y", f"-o{extract_path}", archive_path])
        result = subprocess.run(
            [seven_zip_path, "x", f"-p{candidate}", "-y", f"-o{extract_path}", archive_path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        log.debug("%s - %s", result.stdout, result.stderr)
        if result.returncode == 0:
            return
        if b"Wrong password" not in result.stderr + result.stdout:
            details = (result.stderr or result.stdout).decode(errors="replace").strip()
            current_entries = set(os.listdir(extract_path)) if os.path.exists(extract_path) else set()
            if current_entries - existing_entries:
                log.warning(
                    "7z exited with code %s while extracting %s, continuing with extracted files: %s",
                    result.returncode,
                    archive_path,
                    details,
                )
                return
            raise CuckooPackageError(f"Unable to extract archive: {details}")
        log.debug("The provided password '%s' was incorrect", str(candidate))
        _cleanup_new_entries(extract_path, existing_entries)

    raise CuckooPackageError("Wrong password(s) provided")


def get_file_names(seven_zip_path, archive_path, password="infected", try_multiple_passwords=False):
    """Get the file names from archive file.
    @param seven_zip_path: path to 7z binary
    @param archive_path: archive file path
    @param password: archive password
    @param try_multiple_passwords: split password on ':' and try each
    @return: A list of file names
    """
    password = password or "infected"
    passwords = ([p for p in password.split(":") if p] or ["infected"]) if try_multiple_passwords else [password]

    for candidate in passwords:
        cmd = [seven_zip_path, "l", "-y", f"-p{candidate}", "-sccUTF-8", archive_path]
        log.debug(cmd)
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if "Wrong password" in (p.stdout + p.stderr):
            continue

        stdoutput_lines = p.stdout.splitlines()
        in_table = False
        items_under_header = False
        file_names = []
        name_col_index = 53
        for line in stdoutput_lines:
            if in_table:
                if "-----" in line:
                    if items_under_header:
                        items_under_header = False
                    else:
                        items_under_header = True
                        last_space = line.rfind(" ")
                        if last_space != -1:
                            name_col_index = last_space + 1
                    continue
                if items_under_header:
                    if len(line) > name_col_index:
                        file_name = line[name_col_index:].strip()
                        if file_name:
                            file_names.append(file_name)
            else:
                if all(
                    item.lower() in line.lower()
                    for item in (
                        "Date",
                        "Time",
                        "Attr",
                        "Size",
                        "Compressed",
                        "Name",
                    )
                ):
                    in_table = True
        return file_names

    return []


def extract_zip(zip_path, extract_path, password=b"infected", recursion_depth=1, try_multiple_passwords=False):
    """Extracts a nested ZIP file.
    @param zip_path: ZIP path
    @param extract_path: where to extract
    @param password: ZIP password
    @param recursion_depth: how deep we are in a nested archive
    @param try_multiple_passwords: we will be splitting the password on the ':' symbol,
        and trying each one to extract the archive
    """
    # Test if zip file contains a file named as itself.
    if is_overwritten(zip_path):
        log.debug("ZIP file contains a file with the same name, original will be overwritten")
        # TODO: add random string.
        new_zip_path = f"{zip_path}.old"
        shutil.move(zip_path, new_zip_path)
        zip_path = new_zip_path

    # requires bytes not str
    if isinstance(password, str):
        password = password.encode()

    # Extraction.
    with ZipFile(zip_path, "r") as archive:
        # Check if the archive is encrypted
        for zip_info in archive.infolist():
            is_encrypted = zip_info.flag_bits & 0x1
            # If encrypted and the user didn't provide a password
            # set to default value
            if is_encrypted and (password in (b"", b"infected")):
                log.debug("Archive is encrypted, using default password value: infected")
                if password == b"":
                    password = b"infected"
                    break
            # Else, either password stays as user specified or archive is not encrypted

        if try_multiple_passwords:
            passwords = password.split(b":")
        else:
            passwords = [password]

        # Let's try every password in our password list until we get it right
        password_fail = False
        for pword in passwords:
            try:
                archive.extractall(path=extract_path, pwd=pword)
                password_fail = False
                break
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file") from e
            except RuntimeError as e:
                if "Bad password for file" in repr(e):
                    log.debug("Password '%s' was unsuccessful in extracting the archive.", str(pword))
                    password_fail = True
                    continue
                else:
                    # Try twice, just for kicks
                    try:
                        archive.extractall(path=extract_path, pwd=pword)
                    except RuntimeError as e:
                        raise CuckooPackageError("Unable to extract Zip file: %s", str(e)) from e
            finally:
                if recursion_depth < 4:
                    # Extract nested archives.
                    for name in archive.namelist():
                        if name.endswith(".zip"):
                            # Recurse.
                            try:
                                extract_zip(
                                    os.path.join(extract_path, name),
                                    extract_path,
                                    # Note that the password list is passed on, not the current password in the iteration
                                    password=password,
                                    recursion_depth=recursion_depth + 1,
                                    try_multiple_passwords=try_multiple_passwords,
                                )
                            except BadZipfile:
                                log.warning(
                                    "Nested file '%s' name ends with .zip extension is not a valid Zip. Skip extraction", name
                                )
                            except RuntimeError as run_err:
                                log.error("Error extracting nested Zip file %s with details: %s", name, run_err)

        if password_fail:
            raise CuckooPackageError("Unable to extract password-protected Zip file with the password(s): %s", str(passwords))


def is_overwritten(zip_path):
    """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
    @param zip_path: zip file path
    @return: comparison boolean
    """
    with ZipFile(zip_path, "r") as archive:
        try:
            # Test if zip file contains a file named as itself.
            return any(name == os.path.basename(zip_path) for name in archive.namelist())
        except BadZipfile as e:
            raise CuckooPackageError("Invalid Zip file") from e


def get_infos(zip_path):
    """Get information from ZIP file.
    @param zip_path: zip file path
    @return: ZipInfo class
    """
    try:
        with ZipFile(zip_path, "r") as archive:
            return archive.infolist()
    except BadZipfile as e:
        raise CuckooPackageError("Invalid Zip file") from e


def winrar_extractor(winrar_binary, extract_path, archive_path, password="infected", try_multiple_passwords=False):
    os.makedirs(extract_path, exist_ok=True)
    existing_entries = set(os.listdir(extract_path))
    password = password or "infected"
    passwords = ([p for p in password.split(":") if p] or ["infected"]) if try_multiple_passwords else [password]

    for candidate in passwords:
        cmd = [winrar_binary, "x", "-ibck", "-y", f"-p{candidate}", archive_path, extract_path]
        log.debug(cmd)
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        log.debug("%s - %s", p.stdout, p.stderr)
        current_entries = set(os.listdir(extract_path))
        if current_entries != existing_entries:
            return os.listdir(extract_path)
        if try_multiple_passwords:
            _cleanup_new_entries(extract_path, existing_entries)

    return os.listdir(extract_path)


def get_interesting_files(file_names):
    """
    Using a regular expression that matches interesting file extensions, return interesting files
    """
    interesting_files = []

    for f in file_names:
        if any(f.lower().endswith(file_ext) for file_ext in FILE_EXT_OF_INTEREST):
            interesting_files.append(f)

    return interesting_files


def upload_extracted_files(root, files_at_root):
    """
    Upload each file that was extracted, for further analysis
    """
    resolved_root = os.path.realpath(root)
    for entry in files_at_root:
        try:
            file_path = os.path.join(root, entry)
            resolved_path = os.path.realpath(file_path)
            if os.path.commonpath((resolved_root, resolved_path)) != resolved_root:
                log.warning("Skipping extracted file %s outside extraction root", entry)
                continue
            if not os.path.isfile(resolved_path):
                log.warning("Skipping non-regular extracted path %s", entry)
                continue
            log.info("Uploading %s to host", str(file_path))
            filename = f"files/{hash_file(hashlib.sha256, file_path)}"
            upload_to_host(file_path, filename, metadata=Path(entry).name, duplicated=False)
        except Exception as e:
            log.warning("Couldn't upload file %s to host %s", str(Path(entry).name), str(e))


def attempt_multiple_passwords(options: dict, password: str) -> bool:
    """Does the user want us to try multiple passwords?"""
    enable_multi_password = options.get(OPT_MULTI_PASSWORD, "")
    if enable_multi_password.lower() in ("on", "yes", "true"):
        # .get("password") defaults to infected but could return an empty string too so we need this check
        # If user has requested we use multiple passwords, separated by colon
        if password and ":" in password:
            return True

    return False


def get_zip_file_names(zip_path):
    """Get information from ZIP file.
    @param zip_path: zip file path
    @return: ZipInfo class
    """
    try:
        with ZipFile(zip_path, "r") as archive:
            return archive.namelist()
    except BadZipfile as e:
        raise CuckooPackageError("Invalid Zip file") from e
