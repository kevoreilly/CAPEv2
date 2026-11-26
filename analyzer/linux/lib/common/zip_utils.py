import bz2
import gzip
import hashlib
import logging
import lzma
import os
import shutil
import stat
import subprocess
import tarfile
import zlib
from pathlib import Path
from zipfile import BadZipfile, ZipFile, is_zipfile

from lib.common.constants import OPT_MULTI_PASSWORD
from lib.common.exceptions import CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

ARCHIVE_EXTENSIONS = (
    ".zip",
    ".7z",
    ".rar",
    ".iso",
    ".udf",
    ".vhd",
    ".vhdx",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".tbz",
    ".tbz2",
    ".xz",
    ".txz",
    ".cab",
)

NON_RECURSIVE_CONTAINER_EXTENSIONS = (
    ".docx",
    ".docm",
    ".dotx",
    ".dotm",
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".xlsb",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppsx",
    ".ppsm",
    ".jar",
    ".apk",
    ".xpi",
    ".crx",
    ".whl",
    ".msix",
    ".msixbundle",
    ".appx",
    ".odt",
    ".ods",
    ".odp",
    ".epub",
    ".onepkg",
)

_COMPRESSED_STREAM_MAGICS = (
    (b"\x1f\x8b", gzip.open, ".gz"),
    (b"BZh", bz2.open, ".bz2"),
    (b"\xfd7zXZ\x00", lzma.open, ".xz"),
)

_ARCHIVE_MAGICS = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"MSCF",
)


def is_wrong_password_error(err) -> bool:
    """Return True when an extraction error indicates an incorrect archive password."""
    msg = str(err).lower()
    return (
        "wrong password" in msg
        or "bad password" in msg
        or "incorrect password" in msg
        or "password-protected" in msg
    )


def _password_candidates(password="infected", try_multiple_passwords=False):
    if isinstance(password, bytes):
        password = password.decode("utf-8", errors="replace")
    password = password or "infected"
    if try_multiple_passwords:
        return [p for p in password.split(":") if p] or ["infected"]
    return [password]


def _read_magic_prefix(file_path, length=64):
    try:
        with open(file_path, "rb") as f:
            return f.read(length)
    except OSError:
        return b""


def is_zip_file(file_path) -> bool:
    try:
        return bool(is_zipfile(file_path))
    except OSError:
        return False


def is_rar_file(file_path) -> bool:
    prefix = _read_magic_prefix(file_path, 8)
    return prefix.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"))


def is_tar_or_compressed(file_path) -> bool:
    prefix = _read_magic_prefix(file_path, 8)
    if any(prefix.startswith(magic) for magic, _, _ in _COMPRESSED_STREAM_MAGICS):
        return True
    try:
        return bool(tarfile.is_tarfile(file_path))
    except OSError:
        return False


def is_probable_archive(file_path) -> bool:
    """Lightweight archive detection used when external identifiers (e.g. file) are absent."""
    lower = os.path.basename(file_path).lower()
    if lower.endswith(NON_RECURSIVE_CONTAINER_EXTENSIONS):
        return False

    prefix = _read_magic_prefix(file_path, 64)
    if any(prefix.startswith(magic) for magic in _ARCHIVE_MAGICS):
        return True

    try:
        size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            if size >= 265:
                f.seek(257)
                if f.read(5) == b"ustar":
                    return True
            if size >= 0x8006:
                f.seek(0x8001)
                if f.read(5) == b"CD001":
                    return True
    except OSError:
        return False

    return lower.endswith(ARCHIVE_EXTENSIONS)


def is_within_root(resolved_root: str, target_path: str) -> bool:
    """Return True if target_path resolves inside resolved_root, handling cross-drive paths safely."""
    try:
        resolved_target = os.path.realpath(target_path)
        return os.path.commonpath((resolved_root, resolved_target)) == resolved_root
    except ValueError:
        return False


def _safe_member_target(resolved_root: str, member_name: str):
    """Resolve an archive member path inside resolved_root, or return None if unsafe."""
    normalized = member_name.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        return None
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    target_path = os.path.join(resolved_root, *parts)
    if not is_within_root(resolved_root, target_path):
        return None
    return target_path


def _cleanup_new_entries(extract_path, existing_entries):
    """Remove any file, symlink, or directory in extract_path not in existing_entries."""
    if not os.path.exists(extract_path):
        os.makedirs(extract_path, mode=0o700, exist_ok=True)
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
    """Extract an archive, including encrypted headers, using the supplied passwords."""
    os.makedirs(extract_path, mode=0o700, exist_ok=True)
    existing_entries = set(os.listdir(extract_path))
    passwords = _password_candidates(password, try_multiple_passwords)
    for candidate in passwords:
        result = subprocess.run(
            [seven_zip_path, "x", f"-p{candidate}", "-y", f"-o{extract_path}", archive_path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return
        if b"wrong password" not in (result.stderr + result.stdout).lower():
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
        # Discard partial members between candidates without relaxing privacy.
        _cleanup_new_entries(extract_path, existing_entries)
    raise CuckooPackageError("Wrong password(s) provided")


def _extract_zip_members_safely(archive: ZipFile, extract_path: str, pwd: bytes):
    resolved_root = os.path.realpath(extract_path)
    for info in archive.infolist():
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            log.warning("Skipping symlink entry in ZIP archive: %s", info.filename)
            continue

        target_path = _safe_member_target(resolved_root, info.filename)
        if target_path is None:
            log.warning("Skipping unsafe ZIP member path: %s", info.filename)
            continue

        if info.is_dir():
            os.makedirs(target_path, exist_ok=True)
            continue

        parent_dir = os.path.dirname(target_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        member_pwd = pwd if (info.flag_bits & 0x1) else None
        with archive.open(info, "r", pwd=member_pwd) as src, open(target_path, "wb") as dst:
            shutil.copyfileobj(src, dst)


def extract_zip(
    zip_path,
    extract_path,
    password=b"infected",
    recursion_depth=1,
    try_multiple_passwords=False,
    recursive=True,
):
    """Extracts a ZIP file (optionally recursing nested .zip files).
    @param zip_path: ZIP path
    @param extract_path: where to extract
    @param password: ZIP password
    @param recursion_depth: how deep we are in a nested archive
    @param try_multiple_passwords: we will be splitting the password on the ':' symbol,
        and trying each one to extract the archive
    @param recursive: when True, recurse into nested .zip members up to depth 4
    """
    os.makedirs(extract_path, mode=0o700, exist_ok=True)
    existing_entries = set(os.listdir(extract_path))

    # Test if zip file contains a file named as itself in the same directory.
    if (
        os.path.realpath(os.path.dirname(os.path.abspath(zip_path))) == os.path.realpath(extract_path)
        and is_overwritten(zip_path)
    ):
        log.debug("ZIP file contains a file with the same name, original will be overwritten")
        # TODO: add random string.
        new_zip_path = f"{zip_path}.old"
        shutil.move(zip_path, new_zip_path)
        zip_path = new_zip_path

    # requires bytes not str
    if password is None:
        password = b""
    elif isinstance(password, str):
        password = password.encode()

    # Extraction.
    try:
        archive = ZipFile(zip_path, "r")
    except BadZipfile as e:
        raise CuckooPackageError("Invalid Zip file") from e

    with archive:
        # Check if the archive is encrypted
        is_archive_encrypted = False
        for zip_info in archive.infolist():
            if zip_info.flag_bits & 0x1:
                is_archive_encrypted = True
                # If encrypted and the user didn't provide a password
                # set to default value
                if password in (b"", b"infected"):
                    log.debug("Archive is encrypted, using default password value: infected")
                    if password == b"":
                        password = b"infected"
                break
            # Else, either password stays as user specified or archive is not encrypted

        if try_multiple_passwords:
            passwords = [p for p in password.split(b":") if p] or [b"infected"]
        else:
            passwords = [password]

        # Let's try every password in our password list until we get it right
        password_fail = False
        extracted_ok = False
        for pword in passwords:
            try:
                _extract_zip_members_safely(archive, extract_path, pword)
                password_fail = False
                extracted_ok = True
                break
            except NotImplementedError as e:
                _cleanup_new_entries(extract_path, existing_entries)
                raise CuckooPackageError(f"Unsupported Zip compression or encryption: {e}") from e
            except BadZipfile as e:
                _cleanup_new_entries(extract_path, existing_entries)
                if is_archive_encrypted and "Bad CRC-32" in str(e):
                    log.debug("Password '%s' failed CRC check while extracting ZIP.", str(pword))
                    password_fail = True
                    continue
                raise CuckooPackageError("Invalid Zip file") from e
            except zlib.error as e:
                _cleanup_new_entries(extract_path, existing_entries)
                if is_archive_encrypted:
                    log.debug("Password '%s' failed decompression while extracting ZIP.", str(pword))
                    password_fail = True
                    continue
                raise CuckooPackageError(f"Unable to extract Zip file: {e}") from e
            except RuntimeError as e:
                _cleanup_new_entries(extract_path, existing_entries)
                if "Bad password for file" in repr(e) or "password required" in str(e).lower():
                    log.debug("Password '%s' was unsuccessful in extracting the archive.", str(pword))
                    password_fail = True
                    continue
                raise CuckooPackageError(f"Unable to extract Zip file: {e}") from e
            except OSError as e:
                _cleanup_new_entries(extract_path, existing_entries)
                raise CuckooPackageError(f"Unable to extract Zip file: {e}") from e

        if password_fail:
            raise CuckooPackageError(f"Wrong password(s) provided for Zip archive: {passwords}")

        if extracted_ok and recursive and recursion_depth < 4:
            # Extract nested archives.
            for name in archive.namelist():
                if name.lower().endswith(".zip"):
                    nested_path = _safe_member_target(os.path.realpath(extract_path), name)
                    if not nested_path or not os.path.isfile(nested_path):
                        continue
                    try:
                        extract_zip(
                            nested_path,
                            extract_path,
                            # Note that the password list is passed on, not the current password in the iteration
                            password=password,
                            recursion_depth=recursion_depth + 1,
                            try_multiple_passwords=try_multiple_passwords,
                            recursive=True,
                        )
                    except (BadZipfile, CuckooPackageError) as err:
                        log.warning(
                            "Nested file '%s' could not be extracted as Zip (%s). Skip extraction",
                            name,
                            err,
                        )
                    except RuntimeError as run_err:
                        log.error("Error extracting nested Zip file %s with details: %s", name, run_err)


def extract_tar(archive_path, extract_path):
    """Safely extract a tar archive (plain, gz, bz2, xz) using Python stdlib tarfile."""
    os.makedirs(extract_path, mode=0o700, exist_ok=True)
    resolved_root = os.path.realpath(extract_path)
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                if member.issym() or member.islnk() or member.isdev():
                    log.warning("Skipping non-regular TAR member: %s", member.name)
                    continue
                target_path = _safe_member_target(resolved_root, member.name)
                if target_path is None:
                    log.warning("Skipping unsafe TAR member path: %s", member.name)
                    continue
                if member.isdir():
                    os.makedirs(target_path, exist_ok=True)
                elif member.isfile():
                    parent_dir = os.path.dirname(target_path)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok=True)
                    src = archive.extractfile(member)
                    if src is None:
                        continue
                    with src, open(target_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise CuckooPackageError(f"Unable to extract TAR archive: {e}") from e


def extract_compressed_stream(archive_path, extract_path):
    """Decompress a single-file gzip/bzip2/xz stream into extract_path."""
    prefix = _read_magic_prefix(archive_path, 8)
    opener = None
    default_suffix = ""
    for magic, candidate_opener, suffix in _COMPRESSED_STREAM_MAGICS:
        if prefix.startswith(magic):
            opener = candidate_opener
            default_suffix = suffix
            break

    if opener is None:
        raise CuckooPackageError("Unsupported compressed stream format")

    os.makedirs(extract_path, mode=0o700, exist_ok=True)
    base_name = os.path.basename(archive_path)
    if base_name.lower().endswith(default_suffix) and len(base_name) > len(default_suffix):
        out_name = base_name[: -len(default_suffix)]
    else:
        out_name = f"{base_name}.extracted"

    resolved_root = os.path.realpath(extract_path)
    target_path = _safe_member_target(resolved_root, out_name)
    if target_path is None:
        target_path = os.path.join(resolved_root, "extracted.bin")

    try:
        with opener(archive_path, "rb") as src, open(target_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as e:
        if os.path.exists(target_path):
            try:
                os.unlink(target_path)
            except OSError:
                pass
        raise CuckooPackageError(f"Unable to decompress stream: {e}") from e


def is_overwritten(zip_path):
    """Checks if the ZIP file contains another file with the same name, so it is going to be overwritten.
    @param zip_path: zip file path
    @return: comparison boolean
    """
    try:
        with ZipFile(zip_path, "r") as archive:
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


def unrar_extractor(unrar_binary, extract_path, archive_path, password="infected", try_multiple_passwords=False):
    os.makedirs(extract_path, mode=0o700, exist_ok=True)
    existing_entries = set(os.listdir(extract_path))
    dest_arg = extract_path.rstrip("\\/") + os.sep
    passwords = _password_candidates(password, try_multiple_passwords)
    wrong_password = False
    last_error = ""

    for candidate in passwords:
        cmd = [unrar_binary, "x", "-y", "-o+", f"-p{candidate}", archive_path, dest_arg]
        log.debug(cmd)
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
        # stdoutput, stderr = p.stdout, p.stderr
        log.debug("%s - %s", p.stdout, p.stderr)
        combined = (p.stderr or b"") + (p.stdout or b"")
        combined_lower = combined.lower()
        if p.returncode == 11 or b"wrong password" in combined_lower or b"incorrect password" in combined_lower:
            wrong_password = True
            _cleanup_new_entries(extract_path, existing_entries)
            continue

        if p.returncode == 0:
            return os.listdir(extract_path)

        current_entries = set(os.listdir(extract_path))
        if current_entries - existing_entries:
            details = combined.decode(errors="replace").strip() or f"exit code {p.returncode}"
            log.warning(
                "unrar exited with code %s while extracting %s, continuing with extracted files: %s",
                p.returncode,
                archive_path,
                details,
            )
            return os.listdir(extract_path)

        last_error = combined.decode(errors="replace").strip() or f"exit code {p.returncode}"
        if try_multiple_passwords:
            _cleanup_new_entries(extract_path, existing_entries)

    if wrong_password:
        raise CuckooPackageError("Wrong password(s) provided")
    if last_error:
        raise CuckooPackageError(f"Unable to extract archive with unrar: {last_error}")

    return os.listdir(extract_path)


def upload_extracted_files(root, files_at_root):
    """
    Upload each file that was extracted, for further analysis
    """
    resolved_root = os.path.realpath(root)
    for entry in files_at_root:
        try:
            file_path = os.path.join(root, entry)
            resolved_path = os.path.realpath(file_path)
            if not is_within_root(resolved_root, resolved_path):
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
    enable_multi_password = str(options.get(OPT_MULTI_PASSWORD, "")).strip().lower()
    if enable_multi_password in ("1", "on", "yes", "true"):
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
