# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import logging
import os
import tempfile
from typing import Any, Dict, List, Tuple, Optional

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_write_file
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.trim_utils import trim_file, trimmed_path
from lib.cuckoo.common.utils import get_options, sanitize_filename

sfFile = False
try:
    # from sflock import __version__ as sf_version
    from sflock import unpack
    from sflock.abstracts import File as sfFile
    from sflock.exception import UnpackException
    from sflock.unpack.office import OfficeFile

    HAS_SFLOCK = True
except ImportError:
    print("\n\n[!] Missing dependencies. Run: poetry install\n\n")
    HAS_SFLOCK = False

log = logging.getLogger(__name__)
cuckoo_conf = Config()
web_cfg = Config("web")
tmp_path = cuckoo_conf.cuckoo.get("tmppath", "/tmp")
linux_enabled = web_cfg.linux.get("enabled", False) or web_cfg.linux.get("static_only", False)

try:
    demux_files_limit = int(web_cfg.general.demux_files_limit)
except ValueError:
    log.error("Invalid value for demux_files_limit in web.conf, defaulting to 10")
    demux_files_limit = 10  # Default value

demux_extensions_list = {
    b".accdr",
    b".exe",
    b".dll",
    b".com",
    b".jar",
    b".pdf",
    b".msi",
    b".msix",
    b".msixbundle",
    b".bin",
    b".scr",
    b".zip",
    b".tar",
    b".gz",
    b".tgz",
    b".rar",
    b".htm",
    b".html",
    b".hta",
    b".doc",
    b".dot",
    b".docx",
    b".dotx",
    b".docm",
    b".dotm",
    b".docb",
    b".mht",
    b".mso",
    b".js",
    b".jse",
    b".vbs",
    b".vbe",
    b".xls",
    b".xlt",
    b".xlm",
    b".xlsx",
    b".xltx",
    b".xlsm",
    b".xltm",
    b".xlsb",
    b".xla",
    b".xlam",
    b".xll",
    b".xlw",
    b".ppt",
    b".pot",
    b".pps",
    b".pptx",
    b".pptm",
    b".potx",
    b".potm",
    b".ppam",
    b".ppsx",
    b".ppsm",
    b".sldx",
    b".sldm",
    b".wsf",
    b".bat",
    b".ps1",
    b".sh",
    b".pl",
    b".lnk",
    b".one",
    b".onetoc2",
}

whitelist_extensions = {"doc", "xls", "ppt", "pub", "jar"}

blacklist_extensions = {"apk", "dmg"}

# list of valid file types to extract - TODO: add more types
VALID_TYPES = {"PE32", "Java Jar", "Outlook", "Message", "MS Windows shortcut", "PDF document", *File.LINUX_TYPES}
VALID_PACKAGES = {"doc", "xls", "ppt", "pdf"}
OFFICE_TYPES = [
    "Composite Document File",
    "CDFV2 Encrypted",
    "Excel 2007+",
    "Word 2007+",
    "Microsoft OOXML",
]


IGNORABLE_PATTERNS = (
    re.compile(br"msvcp\d+\.dll$", re.IGNORECASE),
    re.compile(br"vcruntime\d+(_\d)?\.dll$", re.IGNORECASE),
    re.compile(br"api-ms-win-.*\.dll$", re.IGNORECASE),
    re.compile(br"ucrtbase\.dll$", re.IGNORECASE),
    re.compile(br"concrt\d+\.dll$", re.IGNORECASE),
    re.compile(br"vccorlib\d+\.dll$", re.IGNORECASE),
    # You can add more patterns here, e.g., for .NET runtimes:
    # re.compile(r"coreclr\.dll$", re.IGNORECASE),
    # re.compile(r"System\..*\.dll$", re.IGNORECASE),
)

EXE_PREFERENCE_LIST = (
    b"setup.exe",
    b"install.exe",
    b"installer.exe",
    b"main.exe",
)

FILE_EXT_OF_INTEREST = (
    b".bat",
    b".cmd",
    b".dat",
    b".db",
    # b".dll",
    b".doc",
    b".exe",
    b".html",
    b".js",
    b".jse",
    b".lnk",
    b".msi",
    b".ps1",
    b".scr",
    b".temp",
    b".tmp",
    b".vbe",
    b".vbs",
    b".wsf",
    b".xls",
)


def find_payload_to_run(file_list: List[Any]) -> List[str]:
    """
    Analyzes a list of filenames to find the most likely executable payload.

    Args:
        file_list: A list of filenames (e.g., from zipfile.namelist())

    Returns:
        A list of filenames of the executables to run.
    """

    executables_found = []
    unknown_other_files = []
    ignorable_files_found = 0

    for filename in file_list:
        # Skip empty names (can happen with directory entries)
        if not filename:
            continue

        # Ensure filename is bytes to match regexes and endswith accurately
        filename_bytes = filename if isinstance(filename, bytes) else filename.encode()

        # --- Step 1: Check against Ignorable Patterns ---
        is_ignorable = False
        for pattern in IGNORABLE_PATTERNS:
            if pattern.match(filename_bytes):
                is_ignorable = True
                ignorable_files_found += 1
                break

        if is_ignorable:
            continue # It's a known runtime DLL, skip to the next file

        # --- Step 2: Check for Executable ---
        if filename_bytes.lower().endswith(FILE_EXT_OF_INTEREST):
            executables_found.append(filename_bytes)
            continue

        # --- Step 3: It's an unknown file ---
        unknown_other_files.append(filename_bytes)

    # --- Triage Decision Logic ---

    # Case 1: No executables found at all.
    if not executables_found:
        log.debug("No executables found. Ignored %d runtime files.", ignorable_files_found)
        return []

    # Case 2: Multiple executables found. Use heuristics.
    log.debug("Found multiple executables: %s", str(executables_found))

    # Check against our preferred list
    for preferred_name in EXE_PREFERENCE_LIST:
        for exe_name in executables_found:
            if exe_name.lower() == preferred_name:
                log.debug("Heuristic: Choosing '%s' from preference list.", exe_name)
                return [exe_name.decode(errors="ignore")]

    # if no preferred name, return all files of interest
    return [exe.decode(errors="ignore") for exe in executables_found]

def options2passwd(options: str) -> str:
    password = ""
    if "password=" in options:
        password = get_options(options).get("password")
        if password and isinstance(password, bytes):
            password = password.decode()

    return password


def demux_office(filename: bytes, password: str, platform: str) -> List[bytes]:
    retlist = []
    target_path = os.path.join(tmp_path, "cuckoo-tmp/msoffice-crypt-tmp")
    if not path_exists(target_path):
        path_mkdir(target_path)
    decrypted_name = os.path.join(target_path, os.path.basename(filename).decode())

    if HAS_SFLOCK:
        ofile = OfficeFile(sfFile.from_path(filename))
        d = ofile.decrypt(password)
        # TODO: add decryption verification checks
        if hasattr(d, "contents") and "Encrypted" not in d.magic:
            _ = path_write_file(decrypted_name, d.contents)
            retlist.append((decrypted_name.encode(), platform))
    else:
        raise CuckooDemuxError("MS Office decryptor not available")

    if not retlist:
        retlist.append((filename, platform))

    return retlist


def is_valid_type(magic: str) -> bool:
    # check for valid file types and don't rely just on file extension
    return any(ftype in magic for ftype in VALID_TYPES)


def is_valid_package(package: str) -> bool:
    # check if the file has a valid package type
    if not package:
        return False
    return any(ptype in package for ptype in VALID_PACKAGES)


# list of junk extensions to skip
JUNK_EXTENSIONS = {
    b".yar",
    b".yara",
    b".md",
    b".txt",
    b".yml",
    b".yaml",
    b".gitignore",
    b".gitattributes",
    b".gitmodules",
}

JUNK_NAMES = {b"license", b"copying", b"makefile", b"authors", b"readme"}


# ToDo fix return type
def _sf_children(child: Any) -> Tuple[bytes, str, str, int]:
    path_to_extract = b""
    filename_lower = child.filename.lower()

    # Skip junk files
    if any(filename_lower.endswith(ext) for ext in JUNK_EXTENSIONS):
        return b"", child.platform, child.magic, child.filesize
    if any(name in filename_lower for name in JUNK_NAMES):
        return b"", child.platform, child.magic, child.filesize
    if b".github/" in filename_lower or b".git/" in filename_lower:
        return b"", child.platform, child.magic, child.filesize

    _, ext = os.path.splitext(child.filename)
    ext = ext.lower()
    if (
        ext in demux_extensions_list
        or is_valid_package(child.package)
        or is_valid_type(child.magic)
        or (not ext and is_valid_type(child.magic))
        # msix
        or all([pattern in child.contents for pattern in (b"Registry.dat", b"AppxManifest.xml")])
    ):
        target_path = os.path.join(tmp_path, "cuckoo-sflock")
        if not path_exists(target_path):
            path_mkdir(target_path)
        tmp_dir = tempfile.mkdtemp(dir=target_path)
        try:
            if child.contents:
                path_to_extract = os.path.join(tmp_dir, sanitize_filename((child.filename).decode())).encode()
                _ = path_write_file(path_to_extract, child.contents)
        except Exception as e:
            log.exception(e)
    return path_to_extract, child.platform, child.magic or "", child.filesize


# ToDo fix typing need to add str as error msg
def demux_sflock(
    filename: bytes, options: str, check_shellcode: bool = True
) -> Tuple[List[Tuple[bytes, str, str, int]], str, List[str]]:
    retlist = []
    submit_opts = []
    # do not extract from .bin (downloaded from us)
    if os.path.splitext(filename)[1] == b".bin":
        return retlist, "", submit_opts

    # ToDo need to introduce error msgs here
    try:
        platform = ""
        magic_type = ""
        file_size = 0

        # Before unpacking, ensure the file actually exists and is not empty to avoid IncorrectUsageException
        if not path_exists(filename) or os.path.getsize(filename) == 0:
            return [(filename, platform, magic_type, file_size)], "file not found or empty", []

        password = options2passwd(options) or "infected"
        try:
            unpacked = unpack(filename, password=password, check_shellcode=check_shellcode)
        except UnpackException:
            unpacked = unpack(filename, check_shellcode=check_shellcode)

        if unpacked.package in whitelist_extensions:
            file = File(filename)
            magic_type = file.get_type() or ""
            platform = file.get_platform()
            file_size = file.get_size()
            return [(filename, platform, magic_type, file_size)], "", []
        if unpacked.package in blacklist_extensions:
            return retlist, "blacklisted package", submit_opts

        if unpacked.filepaths:
            # CASE 1: Archive contains multiple files
            if len(unpacked.filepaths) > 1:
                # Find interesting files (exe/dll) and submit the ORIGINAL archive
                # with instructions to run specifically those files.
                execs = find_payload_to_run(unpacked.filepaths)
                submit_opts = [f"file={runable}" for runable in execs]
                # returning empty retlist so it will use parent file
                return [], "", submit_opts

            # CASE 2: Archive contains exactly 1 file
            single_file = unpacked.filepaths[0]
            # assuming unpacked.children matches unpacked.filepaths indices
            # we get the object representing this single file
            current_child = unpacked.children[0] if unpacked.children else None

            if current_child:
                if single_file.endswith((b".7z", b".rar", b".zip")):
                    # It's a sub-archive. We need to go one level deeper.
                    # We loop through THIS sub-archive's children.
                    # Note: Ensure 'current_child.children' exists in your object model.
                    # If 'unpacked.children' already contained the deep files, this loop might need adjusting based on your specific API.
                    execs = find_payload_to_run(getattr(current_child, "filepaths", []))
                    if execs:
                        extracted = _sf_children(current_child)
                        path = extracted[0]
                        if path:
                            submit_opts += [f"file={runable}" for runable in execs]
                            retlist.append(extracted)
                else:
                    # It's just a single regular file (e.g., malware.exe inside a zip).
                    # Extract and add to task.
                    extracted = _sf_children(current_child)
                    path = extracted[0]
                    if path:
                        retlist.append(extracted)
            return retlist, "", submit_opts

        for sf_child in unpacked.children:
            if sf_child.to_dict().get("children"):
                for ch in sf_child.children:
                    tmp_child = _sf_children(ch)
                    # check if path is not empty
                    if tmp_child and tmp_child[0]:
                        retlist.append(tmp_child)

                # child is not available, the original file should be put into the list
                if not retlist:
                    tmp_child = _sf_children(sf_child)
                    # check if path is not empty
                    if tmp_child and tmp_child[0]:
                        retlist.append(tmp_child)
            else:
                tmp_child = _sf_children(sf_child)
                # check if path is not empty
                if tmp_child and tmp_child[0]:
                    retlist.append(tmp_child)
    except Exception as e:
        log.exception(e)
    return list(filter(None, retlist)), "", submit_opts


def _prepare_file(filename: bytes, options: str = "", size: int = 0) -> Tuple[Optional[bytes], Optional[str]]:
    try:
        f_basename = os.path.basename(filename).decode('utf-8', errors='replace')
    except Exception:
        f_basename = "unknown_filename"

    if not size:
        size = File(filename).get_size()
    if size <= web_cfg.general.max_sample_size:
        return filename, None

    safe_options = options or ""
    if web_cfg.general.allow_ignore_size and "ignore_size_check" in safe_options:
        return filename, None

    if web_cfg.general.enable_trim and trim_file(filename):
        return trimmed_path(filename), None

    error_msg = f"File too big ({f_basename}), enable 'allow_ignore_size' in web.conf or use 'ignore_size_check' option"
    return None, error_msg


def demux_sample(
    filename: bytes, package: str, options: str, use_sflock: bool = True, platform: str = ""
) -> Tuple[List[Tuple[bytes, str]], List[Dict[str, str]]]:
    """
    If file is a ZIP, extract its included files and return their file paths
    If file is an email, extracts its attachments and return their file paths (later we'll also extract URLs)
    """
    # Skip junk files
    filename_bytes = filename if isinstance(filename, bytes) else filename.encode()
    filename_lower_bytes = filename_bytes.lower()
    if any(filename_lower_bytes.endswith(ext) for ext in JUNK_EXTENSIONS) or any(
        name in filename_lower_bytes for name in JUNK_NAMES
    ):
        filename_str = filename.decode(errors="ignore") if isinstance(filename, bytes) else filename
        return [], [{"junk_filter": f"File {filename_str} skipped by junk filter"}]

    # sflock requires filename to be bytes object for Py3
    # TODO: Remove after checking all uses of demux_sample use bytes ~TheMythologist
    if isinstance(filename, str) and use_sflock:
        filename = filename.encode()

    error_list = []
    retlist = []

    # --- 1. Quick Handle: Specific Package ---
    if package:
        if package == "msix":
            return [(filename, "windows")], []

        valid_file, error = _prepare_file(filename, options)
        if valid_file:
            return [(valid_file, platform)], []
        else:
            return [], [{os.path.basename(filename).decode(errors='ignore'): error}]

    # --- 2. File Preparation (Unquarantine) ---
    filename = unquarantine(filename)

    # don't try to extract from office docs
    magic = File(filename).get_type() or ""

    # --- 3. Handle Password-Protected Office Files ---
    is_office = "Microsoft" in magic or any(x in magic for x in OFFICE_TYPES)
    if is_office and use_sflock:
        password = options2passwd(options)
        if HAS_SFLOCK and password:
            retlist = demux_office(filename, password, platform)
            return retlist, error_list
        else:
            log.error("Detected password protected office file, but no sflock is installed.")
            return [], [{os.path.basename(filename).decode(errors='ignore'): "Detected password protected office file, but no sflock is installed"}]

    # --- 4. Skip Extraction for specific types ---
    ignored_signatures = [
        "Java Jar",
        "Java archive data",
        "PE32",
        "MS-DOS executable"
    ]
    # Añadimos tipos de Linux si están definidos
    if hasattr(File, "LINUX_TYPES"):
        ignored_signatures.extend(File.LINUX_TYPES)

    # If magic matches an ignored type, treat as regular file and skip sflock
    if any(sig in magic for sig in ignored_signatures):
        valid_file, error = _prepare_file(filename, options)
        if valid_file:
            return [(valid_file, platform)], []
        else:
            return [], [{os.path.basename(filename).decode(errors='ignore'): error}]

    # --- 5. Generic Extraction (Sflock) ---
    check_shellcode = "check_shellcode=0" not in (options or "")

    # Inicializamos variables de retorno de sflock
    extracted_files = []
    sflock_error = ""
    execs = []

    if HAS_SFLOCK and use_sflock:
        extracted_files, sflock_error, execs = demux_sflock(filename, options, check_shellcode)

    # Si sflock encontró ejecutables específicos que quiere forzar (ej. payload en un zip)
    if execs:
        for opt in execs:
            error_list.append({"option": opt})

    # If nothing extracted (not an archive, or sflock failed/skipped)
    if not extracted_files:
        if sflock_error:
            error_list.append({os.path.basename(filename).decode(errors='ignore'): sflock_error})

        # Fallback: submit the original file
        valid_file, error = _prepare_file(filename, options)
        if valid_file:
            retlist.append((valid_file, platform))
        elif error and not sflock_error:
            # Only report size error if sflock didn't already report a more relevant error
            error_list.append({os.path.basename(filename).decode(errors='ignore'): error})

        return retlist, error_list

    # --- 6. Process Extracted Files ---
    for block in extracted_files:
        if len(retlist) >= demux_files_limit:
            break

        ex_filename, ex_platform, ex_magic, ex_size = block
        f_basename_str = os.path.basename(ex_filename).decode(errors='ignore')

        # Platform check (Linux)
        if ex_platform == "linux" and not linux_enabled and "Python" not in ex_magic:
            error_list.append({f_basename_str: "Linux processing is disabled"})
            continue

        # Validate size and trim if necessary
        # Pass 'ex_size' to _prepare_file to avoid re-calculating it
        valid_file, error = _prepare_file(ex_filename, options, size=ex_size)

        if valid_file:
            retlist.append((valid_file, ex_platform))
        else:
            error_list.append({f_basename_str: error})

    return retlist, error_list
