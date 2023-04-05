# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import errno
import fcntl
import inspect
import logging
import multiprocessing
import os
import random
import shutil
import socket
import string
import struct
import sys
import tempfile
import threading
import time
import xmlrpc.client
import zipfile
from datetime import datetime
from io import BytesIO
from typing import Tuple, Union

from data.family_detection_names import family_detection_names
from lib.cuckoo.common import utils_dicts
from lib.cuckoo.common import utils_pretty_print_funcs as pp_funcs
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_exists, path_get_filename, path_is_dir, path_mkdir, path_read_file

try:
    import re2 as re
except ImportError:
    import re

try:
    import chardet

    HAVE_CHARDET = True
except ImportError:
    HAVE_CHARDET = False

try:
    import pyzipper

    HAVE_PYZIPPER = True
except ImportError:
    HAVE_PYZIPPER = False
    print("Missed pyzipper dependency: pip3 install pyzipper -U")


def arg_name_clscontext(arg_val):
    val = int(arg_val, 16)
    enumdict = utils_dicts.ClsContextDict()
    return simple_pretty_print_convert(val, enumdict)


config = Config()
web_cfg = Config("web")

HAVE_TMPFS = False
if hasattr(config, "tmpfs"):
    tmpfs = config.tmpfs
    HAVE_TMPFS = True

log = logging.getLogger(__name__)

# Django Validator BSD lic. https://github.com/django/django
referrer_url_re = re.compile(
    r"^(?:http|ftp)s?://"  # http:// or https://
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
    r"localhost|"  # localhost...
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
    r"(?::\d+)?"  # optional port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)

# change to read from config
zippwd = web_cfg.zipped_download.get("zip_pwd", b"infected")
if not isinstance(zippwd, bytes):
    zippwd = zippwd.encode()

max_len = config.cuckoo.get("max_len", 100)
sanitize_len = config.cuckoo.get("sanitize_len", 32)
sanitize_to_len = config.cuckoo.get("sanitize_to_len", 24)


def load_categories():
    analyzing_categories = [category.strip() for category in config.cuckoo.categories.split(",")]
    needs_VM = any([category in analyzing_categories for category in ("file", "url")])
    return analyzing_categories, needs_VM


texttypes = [
    "ASCII",
    "Windows Registry text",
    "XML document text",
    "Unicode text",
]


VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]


def get_platform(magic):
    if magic and any(x in magic for x in VALID_LINUX_TYPES):
        return "linux"
    return "windows"


# this doesn't work for bytes
# textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
# is_binary_file = lambda bytes: bool(bytes.translate(None, textchars))


def make_bytes(value: Union[str, bytes], encoding: str = "latin-1") -> bytes:
    return value.encode(encoding) if isinstance(value, str) else value


def is_text_file(file_info, destination_folder, buf, file_data=False):

    if any(file_type in file_info.get("type", "") for file_type in texttypes):

        extracted_path = os.path.join(
            destination_folder,
            file_info.get(
                "sha256",
            ),
        )
        if not file_data and not path_exists(extracted_path):
            return

        if not file_data:
            file_data = path_read_file(extracted_path)

        if len(file_data) > buf:
            return file_data[:buf].decode("latin-1") + " <truncated>"
        else:
            return file_data.decode("latin-1")


def create_zip(files=False, folder=False, encrypted=False):
    """Utility function to create zip archive with file(s)
    @param files: file or list of files
    @param folder: path to folder to compress
    @param encrypted: create password protected and AES encrypted file
    """

    if folder:
        # To avoid when we have only folder argument
        if not files:
            files = []
        files += [os.path.join(folder, file) for file in os.listdir(folder)]

    if not isinstance(files, list):
        files = [files]

    mem_zip = BytesIO()
    if encrypted and HAVE_PYZIPPER:
        zipper = pyzipper.AESZipFile(mem_zip, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES)
    else:
        zipper = zipfile.ZipFile(mem_zip, "a", zipfile.ZIP_DEFLATED, False)
    with zipper as zf:
        if encrypted:
            zf.setpassword(zippwd)
        for file in files:
            if not path_exists(file):
                log.error("File does't exist: %s", file)
                continue

            parent_folder = os.path.dirname(file).rsplit(os.sep, 1)[-1]
            path = os.path.join(parent_folder, os.path.basename(file))
            zf.write(file, path)

    mem_zip.seek(0)
    return mem_zip


def free_space_monitor(path=False, return_value=False, processing=False, analysis=False):
    """
    @param path: path to check
    @param return_value: return available size
    @param processing: size from cuckoo.conf -> freespace_processing.
    @param analysis: check the main storage size
    """
    need_space, space_available = False, 0
    while True:
        try:
            # Calculate the free disk space in megabytes.
            # Check main FS if processing
            if processing:
                free_space = config.cuckoo.freespace_processing
            elif not analysis and HAVE_TMPFS and tmpfs.enabled:
                path = tmpfs.path
                free_space = tmpfs.freespace
            else:
                free_space = config.cuckoo.freespace

            if path and not path_exists(path):
                sys.exit("Restart daemon/process, happens after full cleanup")
            space_available = shutil.disk_usage(path).free >> 20
            need_space = space_available < free_space
        except FileNotFoundError:
            log.error("Folder doesn't exist, maybe due to clean")
            path_mkdir(path)
            continue

        if return_value:
            return need_space, space_available

        if need_space:
            log.error(
                "Not enough free disk space! (Only %d MB!). You can change limits it in cuckoo.conf -> freespace", space_available
            )
            time.sleep(5)
        else:
            break


def get_memdump_path(memdump_id, analysis_folder=False):
    """
    Get the path of memdump to store
    analysis_folder: force to return default analysis folder
    """
    memdump_id = str(memdump_id)
    return (
        os.path.join(tmpfs.path, f"{memdump_id}.dmp")
        if HAVE_TMPFS and tmpfs.enabled and not analysis_folder
        else os.path.join(CUCKOO_ROOT, "storage", "analyses", memdump_id, "memory.dmp")
    )


def validate_referrer(url):
    if not url:
        return None

    if not referrer_url_re.match(url):
        return None

    return url


def create_folders(root=".", folders=None):
    """Create directories.
    @param root: root path.
    @param folders: folders list to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    if not folders:
        return

    for folder in folders:
        create_folder(root, folder)


def create_folder(root=".", folder=None):
    """Create directory.
    @param root: root path.
    @param folder: folder name to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
    if folder is None:
        raise CuckooOperationalError("Can not create None type folder")
    folder_path = os.path.join(root, folder)
    if folder and not path_is_dir(folder_path):
        try:
            path_mkdir(folder_path, parent=True)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise CuckooOperationalError(f"Unable to create folder: {folder_path}") from e
        except Exception as e:
            print(e)


def delete_folder(folder):
    """Delete a folder and all its subdirectories.
    @param folder: path to delete.
    @raise CuckooOperationalError: if fails to delete folder.
    """
    if path_exists(folder):
        try:
            shutil.rmtree(folder)
        except OSError as e:
            raise CuckooOperationalError(f"Unable to delete folder: {folder}") from e


# Don't allow all characters in "string.printable", as newlines, carriage
# returns, tabs, \x0b, and \x0c may mess up reports.
# The above is true, but apparently we only care about \x0b and \x0c given
# the code below
PRINTABLE_CHARACTERS = string.ascii_letters + string.digits + string.punctuation + " \t\r\n"
FILENAME_CHARACTERS = string.ascii_letters + string.digits + string.punctuation.replace("/", "") + " "


def convert_char(c):
    """Escapes characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if isinstance(c, int):
        c = chr(c)
    return c if c in PRINTABLE_CHARACTERS else f"\\x{ord(c):02x}"


def is_printable(s):
    """Test if a string is printable."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in PRINTABLE_CHARACTERS:
            return False
    return True


def bytes2str(convert):
    """Converts bytes to string
    @param convert: string as bytes.
    @return: string.
    """
    if isinstance(convert, bytes):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    if isinstance(convert, bytearray):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    items = []
    if isinstance(convert, dict):
        tmp_dict = {}
        items = convert.items()
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    tmp_dict[k] = v.decode()
                except UnicodeDecodeError:
                    tmp_dict[k] = "".join(str(ord(_)) for _ in v)
        return tmp_dict
    elif isinstance(convert, list):
        converted_list = []
        items = enumerate(convert)
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    converted_list.append(v.decode())
                except UnicodeDecodeError:
                    converted_list.append("".join(str(ord(_)) for _ in v))

        return converted_list

    return convert


def convert_to_printable(s: str, cache=None):
    """Convert char to printable.
    @param s: string.
    @param cache: an optional cache
    @return: sanitized string.
    """
    if isinstance(s, int):
        return str(s)

    if isinstance(s, bytes):
        return bytes2str(s)

    if is_printable(s):
        return s

    if cache is None:
        return "".join(convert_char(c) for c in s)
    elif s not in cache:
        cache[s] = "".join(convert_char(c) for c in s)
    return cache[s]


def convert_to_printable_and_truncate(s: str, buf: int, cache=None):
    return convert_to_printable(f"{s[:buf]} <truncated>" if len(s) > buf else s, cache=cache)


def convert_filename_char(c):
    """Escapes filename characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if isinstance(c, int):
        c = chr(c)
    return c if c in FILENAME_CHARACTERS else f"\\x{ord(c):02x}"


def is_sane_filename(s):
    """Test if a filename is sane."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in FILENAME_CHARACTERS:
            return False
    return True


def wide2str(string: Tuple[str, bytes]):
    """wide string detection, for strings longer than 11 chars

    Doesn't work:
        string.decode("utf-16").encode('ascii')
        ccharted
    Do you have better solution?
    """
    null_byte = 0 if isinstance(string, bytes) else "\x00"
    if (
        len(string) < 11
        or any(string[char] != null_byte for char in (1, 3, 5, 7, 9, 11))
        or any(string[char] == null_byte for char in (0, 2, 4, 6, 8, 10))
    ):
        return string
    if isinstance(string, bytes):
        return string.decode("utf-16")
    return string.encode().decode("utf-16")


def sanitize_pathname(s: str):
    """Sanitize filename.
    @param s: string.
    @return: sanitized filename.
    """
    if is_sane_filename(s):
        return s

    return "".join(convert_filename_char(c) for c in s)


def simple_pretty_print_convert(argval, enumdict):
    retnames = []
    leftover = argval
    for key, value in enumdict.items():
        if argval & value:
            leftover &= ~value
            retnames.append(key)

    if leftover:
        retnames.append(f"0x{leftover:08x}")

    return "|".join(retnames)


def pretty_print_retval(status, retval):
    """Creates pretty-printed versions of an API return value
    @return: pretty-printed version of the call's return value, or None if no conversion exists
    """
    if status:
        return None
    val = None
    try:
        val = int(retval, 16) & 0xFFFFFFFF
    except ValueError:
        return None
    return {
        0x00000103: "NO_MORE_ITEMS",
        0x00002AF9: "WSAHOST_NOT_FOUND",
        0x00002AFC: "WSANO_DATA",
        0x80000005: "BUFFER_OVERFLOW",
        0x80000006: "NO_MORE_FILES",
        0x8000000A: "HANDLES_CLOSED",
        0x8000001A: "NO_MORE_ENTRIES",
        0xC0000001: "UNSUCCESSFUL",
        0xC0000002: "NOT_IMPLEMENTED",
        0xC0000004: "INFO_LENGTH_MISMATCH",
        0xC0000005: "ACCESS_VIOLATION",
        0xC0000008: "INVALID_HANDLE",
        0xC000000B: "INVALID_CID",
        0xC000000D: "INVALID_PARAMETER",
        0xC000000F: "NO_SUCH_FILE",
        0xC0000011: "END_OF_FILE",
        0xC0000018: "CONFLICTING_ADDRESSES",
        0xC0000022: "ACCESS_DENIED",
        0xC0000023: "BUFFER_TOO_SMALL",
        0xC0000024: "OBJECT_TYPE_MISMATCH",
        0xC0000033: "OBJECT_NAME_INVALID",
        0xC0000034: "OBJECT_NAME_NOT_FOUND",
        0xC0000035: "OBJECT_NAME_COLLISION",
        0xC0000039: "OBJECT_PATH_INVALID",
        0xC000003A: "OBJECT_PATH_NOT_FOUND",
        0xC000003C: "DATA_OVERRUN",
        0xC0000043: "SHARING_VIOLATION",
        0xC0000045: "INVALID_PAGE_PROTECTION",
        0xC000007A: "PROCEDURE_NOT_FOUND",
        0xC00000AC: "PIPE_NOT_AVAILABLE",
        0xC00000BA: "FILE_IS_A_DIRECTORY",
        0xC000010A: "PROCESS_IS_TERMINATING",
        0xC0000121: "CANNOT_DELETE",
        0xC0000135: "DLL_NOT_FOUND",
        0xC0000139: "ENTRYPOINT_NOT_FOUND",
        0xC0000142: "DLL_INIT_FAILED",
        0xC000014B: "PIPE_BROKEN",
        0xC0000225: "NOT_FOUND",
    }.get(val)


def pretty_print_arg(category, api_name, arg_name, arg_val):
    """Creates pretty-printed versions of API arguments that convert raw values in common APIs to their named-enumeration forms
    @return: pretty-printed version of the argument value provided, or None if no conversion exists
    """
    if api_name == "NtCreateSection" and arg_name == "DesiredAccess":
        return pp_funcs.api_name_ntcreatesection_arg_name_desiredaccess(arg_val)
    elif api_name == "CreateToolhelp32Snapshot" and arg_name == "Flags":
        return pp_funcs.api_name_createtoolhelp32snapshot_arg_name_flags(arg_val)
    elif arg_name == "ClsContext":
        return arg_name_clscontext(arg_val)
    elif arg_name == "BlobType":
        return pp_funcs.blobtype(arg_val)
    elif arg_name == "Algid":
        return pp_funcs.algid(arg_val)
    elif api_name == "SHGetFolderPathW" and arg_name == "Folder":
        return pp_funcs.api_name_shgetfolderpathw_arg_name_folder(arg_val)
    elif arg_name == "HookIdentifier":
        return pp_funcs.hookidentifer(arg_val)
    elif arg_name == "InfoLevel":
        return pp_funcs.infolevel(arg_val)

    elif arg_name == "Disposition":
        return pp_funcs.disposition(arg_val)
    elif arg_name == "CreateDisposition":
        return pp_funcs.createdisposition(arg_val)
    elif arg_name == "ShareAccess":
        return pp_funcs.shareaccess(arg_val)
    elif arg_name == "SystemInformationClass":
        return pp_funcs.systeminformationclass(arg_val)
    elif category == "registry" and arg_name == "Type":
        return pp_funcs.category_registry_arg_name_type(arg_val)
    elif api_name in {"OpenSCManagerA", "OpenSCManagerW"} and arg_name == "DesiredAccess":
        return pp_funcs.api_name_opensc_arg_name_desiredaccess(arg_val)
    elif category == "services" and arg_name == "ControlCode":
        return pp_funcs.category_services_arg_name_controlcode(arg_val)
    elif category == "services" and arg_name == "ErrorControl":
        return pp_funcs.category_services_arg_name_errorcontrol(arg_val)
    elif category == "services" and arg_name == "StartType":
        return pp_funcs.category_services_arg_name_starttype(arg_val)
    elif category == "services" and arg_name == "ServiceType":
        return pp_funcs.category_services_arg_name_servicetype(arg_val)
    elif category == "services" and arg_name == "DesiredAccess":
        return pp_funcs.category_services_arg_name_desiredaccess(arg_val)
    elif category == "registry" and arg_name in {"Access", "DesiredAccess"}:
        return pp_funcs.category_registry_arg_name_access_desired_access(arg_val)
    elif arg_name == "IoControlCode":
        return pp_funcs.arg_name_iocontrolcode(arg_val)
    elif arg_name in {"Protection", "Win32Protect", "NewAccessProtection", "OldAccessProtection", "OldProtection"}:
        return pp_funcs.arg_name_protection_and_others(arg_val)
    elif (
        api_name in ("CreateProcessInternalW", "CreateProcessWithTokenW", "CreateProcessWithLogonW") and arg_name == "CreationFlags"
    ):
        return pp_funcs.api_name_in_creation(arg_val)
    elif api_name in {"MoveFileWithProgressW", "MoveFileWithProgressTransactedW"} and arg_name == "Flags":
        return pp_funcs.api_name_move_arg_name_flags(arg_val)
    elif arg_name == "FileAttributes":
        return pp_funcs.arg_name_fileattributes(arg_val)
    elif (
        api_name in {"NtCreateFile", "NtOpenFile", "NtCreateDirectoryObject", "NtOpenDirectoryObject"}
        and arg_name == "DesiredAccess"
    ):
        return pp_funcs.api_name_nt_arg_name_desiredaccess(arg_val)
    elif api_name == "NtOpenProcess" and arg_name == "DesiredAccess":
        return pp_funcs.api_name_ntopenprocess_arg_name_desiredaccess(arg_val)
    elif api_name == "NtOpenThread" and arg_name == "DesiredAccess":
        return pp_funcs.api_name_ntopenthread_arg_name_desiredaccess(arg_val)
    elif api_name == "CoInternetSetFeatureEnabled" and arg_name == "FeatureEntry":
        return pp_funcs.api_name_cointernet_arg_name_featureentry(arg_val)
    elif api_name == "CoInternetSetFeatureEnabled" and arg_name == "Flags":
        return pp_funcs.api_name_cointernet_arg_name_flags(arg_val)

    elif api_name == "InternetSetOptionA" and arg_name == "Option":
        return pp_funcs.api_name_internetsetoptiona_arg_name_option(arg_val)
    elif api_name in ("socket", "WSASocketA", "WSASocketW"):
        return pp_funcs.api_name_socket(arg_val, arg_name)
    elif arg_name == "FileInformationClass":
        return pp_funcs.arg_name_fileinformationclass(arg_val)
    elif arg_name == "ProcessInformationClass":
        return pp_funcs.arg_name_processinformationclass(arg_val)
    elif arg_name == "ThreadInformationClass":
        return pp_funcs.arg_name_threadinformationclass(arg_val)
    elif arg_name == "MemType":
        return pp_funcs.arg_name_memtype(arg_val)
    elif arg_name == "Show":
        return pp_funcs.arg_name_show(arg_val)
    elif arg_name == "Registry":
        return pp_funcs.arg_name_registry(arg_val)

    return None


def datetime_to_iso(timestamp):
    """Parse a datatime string and returns a datetime in iso format.
    @param timestamp: timestamp string
    @return: ISO datetime
    """
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").isoformat()


def store_temp_file(filedata, filename, path=None):
    """Store a temporary file.
    @param filedata: content of the original file.
    @param filename: name of the original file.
    @param path: optional path for temp directory.
    @return: path to the temporary file.
    """
    filename = path_get_filename(filename).encode("utf-8", "replace")

    # Reduce length (100 is arbitrary).
    filename = filename[:max_len]

    # Create temporary directory path.
    if path:
        target_path = path
    else:
        tmp_path = config.cuckoo.get("tmppath", b"/tmp")
        target_path = os.path.join(tmp_path.encode(), b"cuckoo-tmp")
    if not path_exists(target_path.decode()):
        path_mkdir(target_path)

    tmp_dir = tempfile.mkdtemp(prefix=b"upload_", dir=target_path)
    tmp_file_path = os.path.join(tmp_dir, filename)
    with open(tmp_file_path, "wb") as tmp_file:
        # If filedata is file object, do chunked copy.
        if hasattr(filedata, "read"):
            chunk = filedata.read(1024)
            while chunk:
                tmp_file.write(chunk)
                chunk = filedata.read(1024)
        else:
            tmp_file.write(filedata)

    return tmp_file_path


def add_family_detection(results: dict, family: str, detected_by: str, detected_on: str):
    results.setdefault("detections", [])
    detection = {detected_by: detected_on}
    # Normalize family names
    family = family_detection_names.get(family, family)
    for block in results["detections"]:
        if family == block.get("family", ""):
            if not any(map(lambda d: d == detection, block["details"])):
                block["details"].append(detection)
            break
    else:
        results["detections"].append({"family": family, "details": [detection]})


def get_clamav_consensus(namelist: list):
    for detection in namelist:
        if detection.startswith("Win.Trojan."):
            words = re.findall(r"[A-Za-z0-9]+", detection)
            family = words[2]
            if family:
                return family


class TimeoutServer(xmlrpc.client.ServerProxy):
    """Timeout server for XMLRPC.
    XMLRPC + timeout - still a bit ugly - but at least gets rid of setdefaulttimeout
    inspired by http://stackoverflow.com/questions/372365/set-timeout-for-xmlrpclib-serverproxy
    (although their stuff was messy, this is cleaner)
    @see: http://stackoverflow.com/questions/372365/set-timeout-for-xmlrpclib-serverproxy
    """

    def __init__(self, *args, **kwargs):
        timeout = kwargs.pop("timeout", None)
        kwargs["transport"] = TimeoutTransport(timeout=timeout)
        xmlrpc.client.ServerProxy.__init__(self, *args, **kwargs)

    def _set_timeout(self, timeout):
        t = self._ServerProxy__transport
        t.timeout = timeout
        # If we still have a socket we need to update that as well.
        if hasattr(t, "_connection") and t._connection[1] and t._connection[1].sock:
            t._connection[1].sock.settimeout(timeout)


class TimeoutTransport(xmlrpc.client.Transport):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop("timeout", None)
        xmlrpc.client.Transport.__init__(self, *args, **kwargs)

    def make_connection(self, *args, **kwargs):
        conn = xmlrpc.client.Transport.make_connection(self, *args, **kwargs)
        if self.timeout is not None:
            conn.timeout = self.timeout
        return conn


class Singleton(type):
    """Singleton.
    @see: http://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
    """

    _instances = {}

    def __call__(self, *args, **kwargs):
        if self not in self._instances:
            self._instances[self] = super(Singleton, self).__call__(*args, **kwargs)
        return self._instances[self]


def logtime(dt):
    """Formats time like a logger does, for the csv output
       (e.g. "2013-01-25 13:21:44,590")
    @param dt: datetime object
    @return: time string
    """
    t = time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
    return f"{t},{dt.microsecond // 1000:03d}"


def time_from_cuckoomon(s):
    """Parse time string received from cuckoomon via netlog
    @param s: time string
    @return: datetime object
    """
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S,%f")


def to_unicode(s):
    """Attempt to fix non uft-8 string into utf-8. It tries to guess input encoding,
    if fail retry with a replace strategy (so undetectable chars will be escaped).
    @see: fuller list of encodings at http://docs.python.org/library/codecs.html#standard-encodings
    """

    def brute_enc(s2):
        """Trying to decode via simple brute forcing."""
        encodings = ("ascii", "utf8", "latin1")
        for enc in encodings:
            with contextlib.suppress(UnicodeDecodeError):
                return s2.decode(enc)
        return None

    def chardet_enc(s2):
        """Guess encoding via chardet."""
        enc = chardet.detect(s2)["encoding"]

        with contextlib.suppress(UnicodeDecodeError):
            return s2.decode(enc)
        return None

    # If already in unicode, skip.
    if isinstance(s, str):
        return s

    # First try to decode against a little set of common encodings.
    result = brute_enc(s)

    # Try via chardet.
    if not result and HAVE_CHARDET:
        result = chardet_enc(s)

    # If not possible to convert the input string, try again with a replace strategy.
    if not result:
        result = s.decode(errors="replace")

    return result


def get_user_filename(options, customs):
    # parse options, check pattern
    for block in (options, customs):
        for pattern in ("filename=", "file_name=", "name="):
            if pattern not in block:
                continue
            for option in block.split(","):
                if not option.startswith(pattern):
                    continue
                return option.split(pattern, 2)[1]
    return ""


def generate_fake_name():
    return "".join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(random.randint(5, 15))
    )


def truncate_filename(x):
    truncated = None
    parts = x.rsplit(".", 1)
    if len(parts) > 1:
        # filename has extension
        extension = parts[1]
        name = parts[0][: (sanitize_to_len - (len(extension) + 1))]
        truncated = f"{name}.{extension}"
    elif len(parts) == 1:
        # no extension
        truncated = parts[0][:(sanitize_to_len)]
    else:
        return None
    return truncated


def sanitize_filename(x):
    """Kind of awful but necessary sanitizing of filenames to
    get rid of unicode problems."""
    out = "".join(c if c in string.ascii_letters + string.digits + " _-." else "_" for c in x)

    """Prevent long filenames such as files named by hash
    as some malware checks for this."""
    if len(out) >= sanitize_len:
        out = truncate_filename(out)

    return out


def default_converter(v):
    # Fix signed ints (bson is kind of limited there).
    # Need to account for subclasses since pymongo's bson module
    # uses 'bson.int64.Int64' clwhat ass for 64-bit values.
    if isinstance(v, int) or issubclass(type(v), int):
        return v & 0xFFFFFFFFFFFFFFFF if v & 0xFFFFFFFF00000000 else v & 0xFFFFFFFF
    return v


def classlock(f):
    """Classlock decorator (created for database.Database).
    Used to put a lock to avoid sqlite errors.
    """

    def inner(self, *args, **kwargs):
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)

        if calframe[1][1].endswith("database.py"):
            return f(self, *args, **kwargs)

        with self._lock:
            return f(self, *args, **kwargs)

    return inner


class SuperLock:
    def __init__(self):
        self.tlock = threading.Lock()
        self.mlock = multiprocessing.Lock()

    def __enter__(self):
        self.tlock.acquire()
        self.mlock.acquire()

    def __exit__(self, type, value, traceback):
        self.mlock.release()
        self.tlock.release()


def get_options(optstring: str):
    """Get analysis options.
    @return: options dict.
    """
    # The analysis package can be provided with some options in the following format:
    #   option1=value1,option2=value2,option3=value3
    #
    # Here we parse such options and provide a dictionary that will be made accessible to the analysis package.
    return (
        dict((value.strip() for value in option.split("=", 1)) for option in optstring.split(",") if option and "=" in option)
        if optstring
        else {}
    )


# get iface ip
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname[:15].encode()))[20:24])  # SIOCGIFADDR


def validate_ttp(ttp: str) -> bool:
    regex = r"^(O?[BCTFSU]\d{4}(\.\d{3})?)|(E\d{4}(\.m\d{2})?)$"
    return bool(re.fullmatch(regex, ttp, flags=re.IGNORECASE))
