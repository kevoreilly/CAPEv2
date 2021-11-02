# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import time
import shutil
import ntpath
import string
import random
import struct
import fcntl
import socket
import tempfile
import xmlrpc.client
import errno
import logging
import inspect
import threading
import multiprocessing
import operator
from io import BytesIO
from datetime import datetime
from collections import defaultdict

from typing import Tuple

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common import utils_dicts
from lib.cuckoo.common import utils_pretty_print_funcs as pp_funcs
import six

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
    zippwd = zippwd.encode("utf-8")


def create_zip(files, folder=False):
    """Utility function to create zip archive with file(s)"""
    if not HAVE_PYZIPPER:
        return False

    if folder:
        files = [os.path.join(folder, file) for file in os.listdir(folder)]

    if not isinstance(files, list):
        files = [files]

    mem_zip = BytesIO()
    with pyzipper.AESZipFile(mem_zip, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(zippwd)
        for file in files:
            if not os.path.exists(file):
                log.error(f"File does't exist: {file}")
                continue

            parent_folder = os.path.dirname(file).split(os.sep)[-1]
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
            elif analysis is False and HAVE_TMPFS and tmpfs.enabled:
                path = tmpfs.path
                free_space = tmpfs.freespace
            else:
                free_space = config.cuckoo.freespace

            space_available = shutil.disk_usage(path).free >> 20
            need_space = space_available < free_space
        except FileNotFoundError:
            log.error("Folder doesn't exist, maybe due to clean")
            os.makedirs(path)
            continue

        if return_value:
            return need_space, space_available

        if need_space:
            log.error("Not enough free disk space! (Only %d MB!)", space_available)
            time.sleep(5)
        else:
            break


def get_memdump_path(id, analysis_folder=False):
    """
    Get the path of memdump to store
    analysis_folder: force to return default analysis folder
    """
    id = str(id)
    if HAVE_TMPFS and tmpfs.enabled and analysis_folder is False:
        memdump_path = os.path.join(tmpfs.path, id + ".dmp")
    else:
        memdump_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", id, "memory.dmp")
    return memdump_path


def validate_referrer(url):
    if not url:
        return None

    if not referrer_url_re.match(url):
        return None

    return url


def create_folders(root=".", folders=[]):
    """Create directories.
    @param root: root path.
    @param folders: folders list to be created.
    @raise CuckooOperationalError: if fails to create folder.
    """
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
    if folder and not os.path.isdir(folder_path):
        try:
            os.makedirs(folder_path)
        except OSError as e:
            print(e)
            if e.errno != errno.EEXIST:
                raise CuckooOperationalError("Unable to create folder: %s" % folder_path)
        except Exception as e:
            print(e)


def delete_folder(folder):
    """Delete a folder and all its subdirectories.
    @param folder: path to delete.
    @raise CuckooOperationalError: if fails to delete folder.
    """
    if os.path.exists(folder):
        try:
            shutil.rmtree(folder)
        except OSError:
            raise CuckooOperationalError("Unable to delete folder: " "{0}".format(folder))


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
    if c in PRINTABLE_CHARACTERS:
        return c
    else:
        return "\\x%02x" % ord(c)


def is_printable(s):
    """ Test if a string is printable."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in PRINTABLE_CHARACTERS:
            return False
    return True


def convert_filename_char(c):
    """Escapes filename characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if isinstance(c, int):
        c = chr(c)
    if c in FILENAME_CHARACTERS:
        return c
    else:
        return "\\x%02x" % ord(c)


def is_sane_filename(s):
    """ Test if a filename is sane."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in FILENAME_CHARACTERS:
            return False
    return True


# ToDo improve
def bytes2str(convert):
    """Converts bytes to string
    @param convert: string as bytes.
    @return: string.
    """
    if isinstance(convert, bytes):
        try:
            convert = convert.decode("utf-8")
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    items = list()
    if isinstance(convert, dict):
        tmp_dict = dict()
        items = convert.items()
        for k, v in items:
            if type(v) is bytes:
                try:
                    tmp_dict[k] = v.decode("utf-8")
                except UnicodeDecodeError:
                    tmp_dict[k] = "".join(str(ord(_)) for _ in v)
        return tmp_dict
    elif isinstance(convert, list):
        converted_list = list()
        items = enumerate(convert)
        for k, v in items:
            if type(v) is bytes:
                try:
                    converted_list.append(v.decode("utf-8"))
                except UnicodeDecodeError:
                    converted_list.append("".join(str(ord(_)) for _ in v))

        return converted_list

    return convert


def wide2str(string: Tuple[str, bytes]):
    """wide string detection, for strings longer than 11 chars

    Doesn't work:
        string.decode("utf-16").encode('ascii')
        ccharted
    Do you have better solution?
    """
    null_byte = "\x00"
    if type(string) is bytes:
        null_byte = 0

    if (
        len(string) >= 11
        and all([string[char] == null_byte for char in (1, 3, 5, 7, 9, 11)])
        and all([string[char] != null_byte for char in (0, 2, 4, 6, 8, 10)])
    ):
        if type(string) is bytes:
            return string.decode("utf-16")
        else:
            return string.encode("utf-8").decode("utf-16")
    else:
        return string


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
    elif not s in cache:
        cache[s] = "".join(convert_char(c) for c in s)
    return cache[s]


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
        retnames.append("0x{0:08x}".format(leftover))

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
    }.get(val, None)


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
    elif (api_name == "OpenSCManagerA" or api_name == "OpenSCManagerW") and arg_name == "DesiredAccess":
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
    elif category == "registry" and (arg_name == "Access" or arg_name == "DesiredAccess"):
        return pp_funcs.category_registry_arg_name_access_desired_access(arg_val)
    elif arg_name == "IoControlCode":
        return pp_funcs.arg_name_iocontrolcode(arg_val)
    elif (
        arg_name == "Protection"
        or arg_name == "Win32Protect"
        or arg_name == "NewAccessProtection"
        or arg_name == "OldAccessProtection"
        or arg_name == "OldProtection"
    ):
        return pp_funcs.arg_name_protection_and_others(arg_val)
    elif (
        api_name in ["CreateProcessInternalW", "CreateProcessWithTokenW", "CreateProcessWithLogonW"] and arg_name == "CreationFlags"
    ):
        return pp_funcs.api_name_in_creation(arg_val)
    elif (api_name == "MoveFileWithProgressW" or api_name == "MoveFileWithProgressTransactedW") and arg_name == "Flags":
        return pp_funcs.api_name_move_arg_name_flags(arg_val)
    elif arg_name == "FileAttributes":
        return pp_funcs.arg_name_fileattributes(arg_val)
    elif (
        api_name == "NtCreateFile"
        or api_name == "NtOpenFile"
        or api_name == "NtCreateDirectoryObject"
        or api_name == "NtOpenDirectoryObject"
    ) and arg_name == "DesiredAccess":
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
    elif api_name in ["socket", "WSASocketA", "WSASocketW"]:
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


def get_filename_from_path(path):
    """Cross-platform filename extraction from path.
    @param path: file path.
    @return: filename.
    """
    dirpath, filename = ntpath.split(path)
    return filename if filename else ntpath.basename(dirpath)


def store_temp_file(filedata, filename, path=None):
    """Store a temporary file.
    @param filedata: content of the original file.
    @param filename: name of the original file.
    @param path: optional path for temp directory.
    @return: path to the temporary file.
    """
    filename = get_filename_from_path(filename).encode("utf-8", "replace")

    # Reduce length (100 is arbitrary).
    filename = filename[:100]

    # Create temporary directory path.
    if path:
        target_path = path
    else:
        tmp_path = config.cuckoo.get("tmppath", b"/tmp")
        target_path = os.path.join(tmp_path.encode(), b"cuckoo-tmp")
    if not os.path.exists(target_path):
        os.mkdir(target_path)

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


def get_vt_consensus(namelist):
    banlist = [
        "other",
        "troj",
        "trojan",
        "win32",
        "trojandownloader",
        "trojandropper",
        "dropper",
        "generik",
        "generic",
        "tsgeneric",
        "malware",
        "dldr",
        "downloader",
        "injector",
        "agent",
        "nsis",
        "generickd",
        "genericgb",
        "behaveslike",
        "heur",
        "inject2",
        "trojanspy",
        "trojanpws",
        "reputation",
        "script",
        "w97m",
        "pp97m",
        "lookslike",
        "macro",
        "dloadr",
        "kryptik",
        "graftor",
        "artemis",
        "zbot",
        "w2km",
        "docdl",
        "variant",
        "packed",
        "trojware",
        "worm",
        "genetic",
        "backdoor",
        "email",
        "obfuscated",
        "cryptor",
        "obfus",
        "virus",
        "xpack",
        "crypt",
        "rootkit",
        "malwares",
        "malicious",
        "suspicious",
        "riskware",
        "risk",
        "win64",
        "troj64",
        "drop",
        "hacktool",
        "exploit",
        "msil",
        "inject",
        "dropped",
        "program",
        "unwanted",
        "heuristic",
        "patcher",
        "tool",
        "potentially",
        "rogue",
        "keygen",
        "unsafe",
        "application",
        "risktool",
        "multi",
        "ransom",
        "autoit",
        "yakes",
        "java",
        "ckrf",
        "html",
        "bngv",
        "bnaq",
        "o97m",
        "blqi",
        "bmbg",
        "mikey",
        "kazy",
        "x97m",
        "msword",
        "cozm",
        "eldorado",
        "fakems",
        "cloud",
        "stealer",
        "dangerousobject",
        "symmi",
        "zusy",
        "dynamer",
        "obfsstrm",
        "krypt",
        "linux",
        "unix",
    ]

    finaltoks = defaultdict(int)
    for name in namelist:
        toks = re.findall(r"[A-Za-z0-9]+", name)
        for tok in toks:
            finaltoks[tok.title()] += 1
    for tok in list(finaltoks):
        lowertok = tok.lower()
        accepted = True
        numlist = [x for x in tok if x.isdigit()]
        if len(numlist) > 2 or len(tok) < 4:
            accepted = False
        if accepted:
            for black in banlist:
                if black == lowertok:
                    accepted = False
                    break
        if not accepted:
            del finaltoks[tok]

    sorted_finaltoks = sorted(list(finaltoks.items()), key=operator.itemgetter(1), reverse=True)
    if len(sorted_finaltoks) == 1 and sorted_finaltoks[0][1] >= 2:
        return sorted_finaltoks[0][0]
    elif len(sorted_finaltoks) > 1 and (sorted_finaltoks[0][1] >= sorted_finaltoks[1][1] * 2 or sorted_finaltoks[0][1] > 8):
        return sorted_finaltoks[0][0]
    elif len(sorted_finaltoks) > 1 and sorted_finaltoks[0][1] == sorted_finaltoks[1][1] and sorted_finaltoks[0][1] > 2:
        return sorted_finaltoks[0][0]
    return ""


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

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


def logtime(dt):
    """Formats time like a logger does, for the csv output
       (e.g. "2013-01-25 13:21:44,590")
    @param dt: datetime object
    @return: time string
    """
    t = time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
    s = "%s,%03d" % (t, dt.microsecond / 1000)
    return s


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
            try:
                # ToDo text_type is unicode py2 str py3
                return six.text_type(s2, enc)
            except UnicodeDecodeError:
                pass
        return None

    def chardet_enc(s2):
        """Guess encoding via chardet."""
        enc = chardet.detect(s2)["encoding"]

        try:
            return six.text_type(s2, enc)
        except UnicodeDecodeError:
            pass
        return None

    # If already in unicode, skip.
    if isinstance(s, six.text_type):
        return s

    # First try to decode against a little set of common encodings.
    result = brute_enc(s)

    # Try via chardet.
    if not result and HAVE_CHARDET:
        result = chardet_enc(s)

    # If not possible to convert the input string, try again with
    # a replace strategy.
    if not result:
        result = six.text_type(s, errors="replace")

    return result


def get_user_filename(options, customs):
    opt_filename = ""
    for block in (options, customs):
        for pattern in ("filename=", "file_name=", "name="):
            if pattern in block:
                for option in block.split(","):
                    if option.startswith(pattern):
                        opt_filename = option.split(pattern)[1]
                        break
                if opt_filename:
                    break
        if opt_filename:
            break

    return opt_filename


def generate_fake_name():
    out = "".join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(random.randint(5, 15))
    )
    return out


MAX_FILENAME_LEN = 24


def truncate_filename(x):
    truncated = None
    parts = x.rsplit(".", 1)
    if len(parts) > 1:
        # filename has extension
        extension = parts[1]
        name = parts[0][: (MAX_FILENAME_LEN - (len(extension) + 1))]
        truncated = f"{name}.{extension}"
    elif len(parts) == 1:
        # no extension
        truncated = parts[0][:(MAX_FILENAME_LEN)]
    else:
        return None
    return truncated


def sanitize_filename(x):
    """Kind of awful but necessary sanitizing of filenames to
    get rid of unicode problems."""
    out = ""
    for c in x:
        if c in string.ascii_letters + string.digits + " _-.":
            out += c
        else:
            out += "_"

    """Prevent long filenames such as files named by hash
    as some malware checks for this."""
    if len(out) >= 32:
        out = truncate_filename(out)

    return out


def default_converter(v):
    # Fix signed ints (bson is kind of limited there).
    if type(v) is int:
        return v & 0xFFFFFFFF
    # Need to account for subclasses since pymongo's bson module
    # uses 'bson.int64.Int64' class for 64-bit values.
    elif issubclass(type(v), int):
        if v & 0xFFFFFFFF00000000:
            return v & 0xFFFFFFFFFFFFFFFF
        else:
            return v & 0xFFFFFFFF
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


class SuperLock(object):
    def __init__(self):
        self.tlock = threading.Lock()
        self.mlock = multiprocessing.Lock()

    def __enter__(self):
        self.tlock.acquire()
        self.mlock.acquire()

    def __exit__(self, type, value, traceback):
        self.mlock.release()
        self.tlock.release()


def get_options(optstring):
    """Get analysis options.
    @return: options dict.
    """
    # The analysis package can be provided with some options in the
    # following format:
    #   option1=value1,option2=value2,option3=value3
    #
    # Here we parse such options and provide a dictionary that will be made
    # accessible to the analysis package.
    if not optstring:
        return {}

    return dict((value.strip() for value in option.split("=", 1)) for option in optstring.split(",") if option and "=" in option)


# get iface ip
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname[:15].encode()))[20:24])  # SIOCGIFADDR
