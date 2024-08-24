import hashlib
import logging
import os
import shutil
import subprocess
from pathlib import Path
from zipfile import BadZipfile, ZipFile

try:
    import re2 as re
except ImportError:
    import re

from lib.common.constants import OPT_MULTI_PASSWORD
from lib.common.exceptions import CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

FILE_NAME_REGEX = re.compile("[\s]{2}((?:[a-zA-Z0-9\.\-,_\\\\]+( [a-zA-Z0-9\.\-,_\\\\]+)?)+)\\r")
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


def extract_archive(seven_zip_path, archive_path, extract_path, password="infected", try_multiple_passwords=False):
    """Extracts a nested archive file.
    @param seven_zip_path: path to 7z binary
    @param archive_path: archive path
    @param extract_path: where to extract
    @param password: archive password
    @param try_multiple_passwords: we will be splitting the password on the ':' symbol,
           and trying each one to extract the archive
    """
    log.debug([seven_zip_path, "x", "-p", "-y", f"-o{extract_path}", archive_path])
    p = subprocess.run(
        [seven_zip_path, "x", "-p", "-y", f"-o{extract_path}", archive_path],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    stdoutput, stderr = p.stdout, p.stderr
    log.debug(f"{p.stdout} {p.stderr}")

    if try_multiple_passwords:
        passwords = password.split(":")
    else:
        passwords = [password]

    if b"Wrong password" in stderr:
        if not Path(extract_path).match("local\\temp"):
            shutil.rmtree(extract_path, ignore_errors=True)

        # Default stderr, to be set at each iteration
        stderr = b""

        # Let's try every password in our password list until we get it right
        for pword in passwords:
            log.debug([seven_zip_path, "x", f"-p{pword}", "-y", f"-o{extract_path}", archive_path])
            p = subprocess.run(
                [seven_zip_path, "x", f"-p{pword}", "-y", f"-o{extract_path}", archive_path],
                stdin=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            stdoutput, stderr = p.stdout, p.stderr
            log.debug(f"{p.stdout} {p.stderr}")
            if b"Wrong password" in stderr:
                log.debug(f"The provided password '{pword}' was incorrect")
                continue
            else:
                # We did it!
                break

        # If we have run through the password list and are still receiving a "wrong password" message,
        # we have failed to extract this archive
        if b"Wrong password" in stderr:
            raise Exception("Wrong password(s) provided")

    elif b"Can not open the file as archive" in stdoutput:
        raise TypeError("Unable to open the file as archive")


def get_file_names(seven_zip_path, archive_path):
    """Get the file names from archive file.
    @param seven_zip_path: path to 7z binary
    @param archive_path: archive file path
    @return: A list of file names
    """
    log.debug([seven_zip_path, "l", archive_path])
    p = subprocess.run(
        [seven_zip_path, "l", archive_path], stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=subprocess.PIPE
    )
    stdoutput = p.stdout.decode()
    stdoutput_lines = stdoutput.split("\n")

    in_table = False
    items_under_header = False
    file_names = []
    for line in stdoutput_lines:
        if in_table:
            # This is a line in the table (header or footer separators)
            if "-----" in line:
                if items_under_header:
                    items_under_header = False
                else:
                    items_under_header = True
                continue

            # These are the lines that we care about, since they contain the file names
            if items_under_header:
                # Find the end of the line (\r), note the carriage return since 7zip will run on Windows
                file_name = re.search(FILE_NAME_REGEX, line)
                if file_name:
                    # The first capture group is the whole file name + returns
                    # The second capture group is just the file name
                    file_name = file_name.group(1)
                    file_names.append(file_name)
        else:
            # Table Headers
            if all(item.lower() in line.lower() for item in ("Date", "Time", "Attr", "Size", "Compressed", "Name")):
                in_table = True

    return file_names


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
                    log.debug(f"Password '{pword}' was unsuccessful in extracting the archive.")
                    password_fail = True
                    continue
                else:
                    # Try twice, just for kicks
                    try:
                        archive.extractall(path=extract_path, pwd=pword)
                    except RuntimeError as e:
                        raise CuckooPackageError(f"Unable to extract Zip file: {e}") from e
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
            raise CuckooPackageError(f"Unable to extract password-protected Zip file with the password(s): {passwords}")


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


def winrar_extractor(winrar_binary, extract_path, archive_path):
    log.debug([winrar_binary, "x", archive_path, extract_path])
    p = subprocess.run(
        [winrar_binary, "x", archive_path, extract_path],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    # stdoutput, stderr = p.stdout, p.stderr
    log.debug(p.stdout + p.stderr)

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
    for entry in files_at_root:
        try:
            file_path = os.path.join(root, entry)
            log.info("Uploading {0} to host".format(file_path))
            filename = f"files/{hash_file(hashlib.sha256, file_path)}"
            upload_to_host(file_path, filename, metadata=Path(entry).name, duplicated=False)
        except Exception as e:
            log.warning(f"Couldn't upload file {Path(entry).name} to host {e}")


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
