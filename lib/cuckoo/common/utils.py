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
from datetime import datetime
from collections import defaultdict

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
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

config = Config()

# it called ramfs, but it is tmpfs
if hasattr(config, "ramfs"):
    ramfs = config.ramfs
    HAVE_RAMFS = True
else:
    HAVE_RAMFS = False

log = logging.getLogger(__name__)


def free_space_monitor(path=False, RAM=False, return_value=False):
    need_space, space_available = False, 0
    while True:
        try:
            # Calculate the free disk space in megabytes.
            if RAM and HAVE_RAMFS and ramfs.enabled:
                space_available = shutil.disk_usage(ramfs.path).free >> 20
                need_space = space_available < ramfs.freespace
            else:
                space_available = shutil.disk_usage(path).free >> 20
                need_space = space_available < config.cuckoo.freespace
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
    if HAVE_RAMFS and ramfs.enabled and analysis_folder is False:
        memdump_path = os.path.join(ramfs.path, id + ".dmp")
    else:
        memdump_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", id, "memory.dmp")
    return memdump_path


def validate_referrer(url):
    if not url:
        return None

    # Django Validator BSD lic. https://github.com/django/django
    url_re = re.compile(
        r"^(?:http|ftp)s?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    if not url_re.match(url):
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


def convert_to_printable(s, cache=None):
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


def sanitize_pathname(s):
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


def pretty_print_retval(category, api_name, status, retval):
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
        val = int(arg_val, 16)
        res = []
        if val == 0xF001F:
            return "SECTION_ALL_ACCESS"
        if val & 0xF0000:
            res.append("STANDARD_RIGHTS_REQUIRED")
            val &= ~0xF0000
        if val & 1:
            res.append("SECTION_QUERY")
            val &= ~1
        if val & 4:
            res.append("SECTION_MAP_READ")
            val &= ~4
        if val & 2:
            res.append("SECTION_MAP_WRITE")
            val &= ~2
        if val & 8:
            res.append("SECTION_MAP_EXECUTE")
            val &= ~8
        if val & 0x10:
            res.append("SECTION_EXTEND_SIZE")
            val &= ~0x10
        if val & 0x20:
            res.append("SECTION_MAP_EXECUTE_EXPLICIT")
            val &= ~0x20
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "CreateToolhelp32Snapshot" and arg_name == "Flags":
        val = int(arg_val, 16)
        res = []
        if val == 0xF:
            return "TH32CS_SNAPALL"
        if val & 1:
            res.append("TH32CS_SNAPHEAPLIST")
            val &= ~1
        if val & 2:
            res.append("TH32CS_SNAPPROCESS")
            val &= ~2
        if val & 4:
            res.append("TH32CS_SNAPTHREAD")
            val &= ~4
        if val & 8:
            res.append("TH32CS_SNAPMODULE")
            val &= ~8
        if val & 0x10:
            res.append("TH32CS_SNAPMODULE32")
            val &= ~0x10
        if val & 0x80000000:
            res.append("TH32CS_INHERIT")
            val &= ~0x80000000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "ClsContext":
        val = int(arg_val, 16)
        enumdict = {
            "CLSCTX_INPROC_SERVER": 0x1,
            "CLSCTX_INPROC_HANDLER": 0x2,
            "CLSCTX_LOCAL_SERVER": 0x4,
            "CLSCTX_INPROC_SERVER16": 0x8,
            "CLSCTX_REMOTE_SERVER": 0x10,
            "CLSCTX_INPROC_HANDLER16": 0x20,
            "CLSCTX_NO_CODE_DOWNLOAD": 0x400,
            "CLSCTX_NO_CUSTOM_MARSHAL": 0x1000,
            "CLSCTX_ENABLE_CODE_DOWNLOAD": 0x2000,
            "CLSCTX_NO_FAILURE_LOG": 0x4000,
            "CLSCTX_DISABLE_AAA": 0x8000,
            "CLSCTX_ENABLE_AAA": 0x10000,
            "CLSCTX_FROM_DEFAULT_CONTEXT": 0x20000,
            "CLSCTX_ACTIVATE_32_BIT_SERVER": 0x40000,
            "CLSCTX_ACTIVATE_64_BIT_SERVER": 0x80000,
            "CLSCTX_ENABLE_CLOAKING": 0x100000,
            "CLSCTX_APPCONTAINER": 0x400000,
            "CLSCTX_ACTIVATE_AAA_AS_IU": 0x800000,
            "CLSCTX_PS_DLL": 0x80000000,
        }
        return simple_pretty_print_convert(val, enumdict)
    elif arg_name == "BlobType":
        val = int(arg_val, 10)
        return {
            0x0001: "SIMPLEBLOB",
            0x0006: "PUBLICKEYBLOB",
            0x0007: "PRIVATEKEYBLOB",
            0x0008: "PLAINTEXTKEYBLOB",
            0x0009: "OPAQUEKEYBLOB",
            0x000A: "PUBLICKEYBLOBEX",
            0x000B: "SYMMETRICWRAPKEYBLOB",
            0x000C: "KEYSTATEBLOB",
        }.get(val, None)
    elif arg_name == "Algid":
        val = int(arg_val, 16)
        return {
            0x0001: "AT_KEYEXCHANGE",
            0x0002: "AT_SIGNATURE",
            0x8001: "MD2",
            0x8002: "MD4",
            0x8003: "MD5",
            0x8004: "SHA1",
            0x800C: "SHA_256",
            0x800D: "SHA_384",
            0x800E: "SHA_512",
            0x8005: "MAC",
            0x8009: "HMAC",
            0x2400: "RSA Public Key Signature",
            0x2200: "DSA Public Key Signature",
            0xA400: "RSA Public Key Exchange",
            0x6602: "RC2",
            0x6801: "RC4",
            0x660D: "RC5",
            0x6601: "DES",
            0x6603: "3DES",
            0x6604: "DESX",
            0x6609: "Two-key 3DES",
            0x6611: "AES",
            0x660E: "AES_128",
            0x660F: "AES_192",
            0x6610: "AES_256",
            0xAA03: "AGREEDKEY_ANY",
            0x660C: "CYLINK_MEK",
            0xAA02: "DH_EPHEM",
            0xAA01: "DH_SF",
            0x2200: "DSS_SIGN",
            0xAA05: "ECDH",
            0x2203: "ECDSA",
            0xA001: "ECMQV",
            0x800B: "HASH_REPLACE_OWF",
            0xA003: "HUGHES_MD5",
            0x2000: "NO_SIGN",
        }.get(val, None)
    elif api_name == "SHGetFolderPathW" and arg_name == "Folder":
        val = int(arg_val, 16)
        res = []
        if val & 0x800:
            res.append("CSIDL_FLAG_PER_USER_INIT")
            val &= ~0x800
        if val & 0x1000:
            res.append("CSIDL_FLAG_NO_ALIAS")
            val &= ~0x1000
        if val & 0x2000:
            res.append("CSIDL_FLAG_DONT_UNEXPAND")
            val &= ~0x2000
        if val & 0x4000:
            res.append("CSIDL_FLAG_DONT_VERIFY")
            val &= ~0x4000
        if val & 0x8000:
            res.append("CSIDL_FLAG_CREATE")
            val &= ~0x8000
        folder = {
            0: "CSIDL_DESKTOP",
            1: "CSIDL_INTERNET",
            2: "CSIDL_PROGRAMS",
            3: "CSIDL_CONTROLS",
            4: "CSIDL_PRINTERS",
            5: "CSIDL_MYDOCUMENTS",
            6: "CSIDL_FAVORITES",
            7: "CSIDL_STARTUP",
            8: "CSIDL_RECENT",
            9: "CSIDL_SENDTO",
            10: "CSIDL_BITBUCKET",
            11: "CSIDL_STARTMENU",
            13: "CSIDL_MYMUSIC",
            14: "CSIDL_MYVIDEO",
            16: "CSIDL_DESKTOPDIRECTORY",
            17: "CSIDL_DRIVES",
            18: "CSIDL_NETWORK",
            19: "CSIDL_NETHOOD",
            20: "CSIDL_FONTS",
            21: "CSIDL_TEMPLATES",
            22: "CSIDL_COMMON_STARTMENU",
            23: "CSIDL_COMMON_PROGRAMS",
            24: "CSIDL_COMMON_STARTUP",
            25: "CSIDL_COMMON_DESKTOPDIRECTORY",
            26: "CSIDL_APPDATA",
            27: "CSIDL_PRINTHOOD",
            28: "CSIDL_LOCAL_APPDATA",
            29: "CSIDL_ALTSTARTUP",
            30: "CSIDL_COMMON_ALTSTARTUP",
            31: "CSIDL_COMMON_FAVORITES",
            32: "CSIDL_INTERNET_CACHE",
            33: "CSIDL_COOKIES",
            34: "CSIDL_HISTORY",
            35: "CSIDL_COMMON_APPDATA",
            36: "CSIDL_WINDOWS",
            37: "CSIDL_SYSTEM",
            38: "CSIDL_PROGRAM_FILES",
            39: "CSIDL_MYPICTURES",
            40: "CSIDL_PROFILE",
            41: "CSIDL_SYSTEMX86",
            42: "CSIDL_PROGRAM_FILESX86",
            43: "CSIDL_PROGRAM_FILES_COMMON",
            44: "CSIDL_PROGRAM_FILES_COMMONX86",
            45: "CSIDL_COMMON_TEMPLATES",
            46: "CSIDL_COMMON_DOCUMENTS",
            47: "CSIDL_COMMON_ADMINTOOLS",
            48: "CSIDL_ADMINTOOLS",
            49: "CSIDL_CONNECTIONS",
            53: "CSIDL_COMMON_MUSIC",
            54: "CSIDL_COMMON_PICTURES",
            55: "CSIDL_COMMON_VIDEO",
            56: "CSIDL_RESOURCES",
            57: "CSIDL_RESOURCES_LOCALIZED",
            58: "CSIDL_COMMON_OEM_LINKS",
            59: "CSIDL_CDBURN_AREA",
            61: "CSIDL_COMPUTERSNEARME",
        }.get(val, None)
        if folder:
            res.append(folder)
        else:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "HookIdentifier":
        val = int(arg_val, 10)
        return {
            # cuckoo chooses not to represent this value properly as a -1
            4294967295: "WH_MSGFILTER",
            0: "WH_JOURNALRECORD",
            1: "WH_JOURNALPLAYBACK",
            2: "WH_KEYBOARD",
            3: "WH_GETMESSAGE",
            4: "WH_CALLWNDPROC",
            5: "WH_CBT",
            6: "WH_SYSMSGFILTER",
            7: "WH_MOUSE",
            8: "WH_HARDWARE",
            9: "WH_DEBUG",
            10: "WH_SHELL",
            11: "WH_FOREGROUNDIDLE",
            12: "WH_CALLWNDPROCRET",
            13: "WH_KEYBOARD_LL",
            14: "WH_MOUSE_LL",
        }.get(val, None)
    elif arg_name == "InfoLevel":
        try:
            val = int(arg_val, 16)
        except:
            val = int(arg_val, 10)
        return {
            1: "HTTP_QUERY_CONTENT_TYPE",
            5: "HTTP_QUERY_CONTENT_LENGTH",
            6: "HTTP_QUERY_CONTENT_LANGUAGE",
            9: "HTTP_QUERY_DATE",
            10: "HTTP_QUERY_EXPIRES",
            18: "HTTP_QUERY_VERSION",
            21: "HTTP_QUERY_RAW_HEADERS",
        }.get(val, None)
    elif arg_name == "Disposition":
        val = int(arg_val, 10)
        return {1: "REG_CREATED_NEW_KEY", 2: "REG_OPENED_EXISTING_KEY"}.get(val, None)
    elif arg_name == "CreateDisposition":
        val = int(arg_val, 16)
        return {0: "FILE_SUPERSEDE", 1: "FILE_OPEN", 2: "FILE_CREATE", 3: "FILE_OPEN_IF", 4: "FILE_OVERWRITE", 5: "FILE_OVERWRITE_IF"}.get(
            val, None
        )
    elif arg_name == "ShareAccess":
        val = int(arg_val, 10)
        res = []
        if val & 1:
            res.append("FILE_SHARE_READ")
            val &= ~1
        if val & 2:
            res.append("FILE_SHARE_WRITE")
            val &= ~2
        if val & 4:
            res.append("FILE_SHARE_DELETE")
            val &= ~4
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "SystemInformationClass":
        val = int(arg_val, 10)
        return {
            0: "SystemBasicInformation",
            1: "SystemProcessorInformation",
            2: "SystemPerformanceInformation",
            3: "SystemTimeOfDayInformation",
            4: "SystemPathInformation",
            5: "SystemProcessInformation",
            7: "SystemDeviceInformation",
            8: "SystemProcessorPerformanceInformation",
            11: "SystemModuleInformation",
            17: "SystemObjectInformation",
            21: "SystemFileCacheInformation",
            23: "SystemInterruptInformation",
            33: "SystemExceptionInformation",
            35: "SystemKernelDebuggerInformation",
            44: "SystemCurrentTimeZoneInformation",
            66: "SystemDynamicTimeZoneInformation",
            90: "SystemBootEnvironmentInformation",
            123: "SystemBasicPerformanceInformation",
        }.get(val, None)
    elif category == "registry" and arg_name == "Type":
        val = int(arg_val, 16)
        return {
            0: "REG_NONE",
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            5: "REG_DWORD_BIG_ENDIAN",
            6: "REG_LINK",
            7: "REG_MULTI_SZ",
            8: "REG_RESOURCE_LIST",
            9: "REG_FULL_RESOURCE_DESCRIPTOR",
            10: "REG_RESOURCE_REQUIREMENTS_LIST",
            11: "REG_QWORD",
        }.get(val, None)
    elif (api_name == "OpenSCManagerA" or api_name == "OpenSCManagerW") and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        res = []
        if val == 0x02000000:
            return "MAXIMUM_ALLOWED"
        if val == 0xF003F:
            return "SC_MANAGER_ALL_ACCESS"
        if val & 0x0001:
            res.append("SC_MANAGER_CONNECT")
            val &= ~0x0001
        if val & 0x0002:
            res.append("SC_MANAGER_CREATE_SERVICE")
            val &= ~0x0002
        if val & 0x0004:
            res.append("SC_MANAGER_ENUMERATE_SERVICE")
            val &= ~0x0004
        if val & 0x0008:
            res.append("SC_MANAGER_LOCK")
            val &= ~0x0008
        if val & 0x0010:
            res.append("SC_MANAGER_QUERY_LOCK_STATUS")
            val &= ~0x0010
        if val & 0x0020:
            res.append("SC_MANAGER_MODIFY_BOOT_CONFIG")
            val &= ~0x0020
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif category == "services" and arg_name == "ControlCode":
        val = int(arg_val, 10)
        return {
            1: "SERVICE_CONTROL_STOP",
            2: "SERVICE_CONTROL_PAUSE",
            3: "SERVICE_CONTROL_CONTINUE",
            4: "SERVICE_CONTROL_INTERROGATE",
            6: "SERVICE_CONTROL_PARAMCHANGE",
            7: "SERVICE_CONTROL_NETBINDADD",
            8: "SERVICE_CONTROL_NETBINDREMOVE",
            9: "SERVICE_CONTROL_NETBINDENABLE",
            10: "SERVICE_CONTROL_NETBINDDISABLE",
        }.get(val, None)
    elif category == "services" and arg_name == "ErrorControl":
        val = int(arg_val, 10)
        return {0: "SERVICE_ERROR_IGNORE", 1: "SERVICE_ERROR_NORMAL", 2: "SERVICE_ERROR_SEVERE", 3: "SERVICE_ERROR_CRITICAL"}.get(val, None)
    elif category == "services" and arg_name == "StartType":
        val = int(arg_val, 10)
        return {
            0: "SERVICE_BOOT_START",
            1: "SERVICE_SYSTEM_START",
            2: "SERVICE_AUTO_START",
            3: "SERVICE_DEMAND_START",
            4: "SERVICE_DISABLED",
        }.get(val, None)
    elif category == "services" and arg_name == "ServiceType":
        val = int(arg_val, 10)
        retstr = {
            1: "SERVICE_KERNEL_DRIVER",
            2: "SERVICE_FILE_SYSTEM_DRIVER",
            4: "SERVICE_ADAPTER",
            8: "SERVICE_RECOGNIZED_DRIVER",
            16: "SERVICE_WIN32_OWN_PROCESS",
            32: "SERVICE_WIN32_SHARE_PROCESS",
        }.get(val & 0x3F, None)
        if val & 0x130:
            retstr += "|SERVICE_INTERACTIVE_PROCESS"
        return retstr
    elif category == "services" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        res = []
        if val == 0x02000000:
            return "MAXIMUM_ALLOWED"
        if val == 0xF01FF:
            return "SERVICE_ALL_ACCESS"
        if val & 0x0001:
            res.append("SERVICE_QUERY_CONFIG")
            val &= ~0x0001
        if val & 0x0002:
            res.append("SERVICE_CHANGE_CONFIG")
            val &= ~0x0002
        if val & 0x0004:
            res.append("SERVICE_QUERY_STATUS")
            val &= ~0x0004
        if val & 0x0008:
            res.append("SERVICE_ENUMERATE_DEPENDENTS")
            val &= ~0x0008
        if val & 0x0010:
            res.append("SERVICE_START")
            val &= ~0x0010
        if val & 0x0020:
            res.append("SERVICE_STOP")
            val &= ~0x0020
        if val & 0x0040:
            res.append("SERVICE_PAUSE_CONTINUE")
            val &= ~0x0040
        if val & 0x0080:
            res.append("SERVICE_INTERROGATE")
            val &= ~0x0080
        if val & 0x0100:
            res.append("SERVICE_USER_DEFINED_CONTROL")
            val &= ~0x0100
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif category == "registry" and (arg_name == "Access" or arg_name == "DesiredAccess"):
        val = int(arg_val, 16)
        res = []
        if val == 0x02000000:
            return "MAXIMUM_ALLOWED"
        if val == 0xF003F:
            return "KEY_ALL_ACCESS"
        elif val == 0x20019:
            return "KEY_READ"
        elif val == 0x20006:
            return "KEY_WRITE"
        elif val == 0x2001F:
            return "KEY_READ|KEY_WRITE"

        if val & 0x0001:
            res.append("KEY_QUERY_VALUE")
            val &= ~0x0001
        if val & 0x0002:
            res.append("KEY_SET_VALUE")
            val &= ~0x0002
        if val & 0x0004:
            res.append("KEY_CREATE_SUB_KEY")
            val &= ~0x0004
        if val & 0x0008:
            res.append("KEY_ENUMERATE_SUB_KEYS")
            val &= ~0x0008
        if val & 0x0010:
            res.append("KEY_NOTIFY")
            val &= ~0x0010
        if val & 0x0020:
            res.append("KEY_CREATE_LINK")
            val &= ~0x0020
        if val & 0x0100:
            res.append("KEY_WOW64_64KEY")
            val &= ~0x0100
        if val & 0x0F0000:
            res.append("STANDARD_RIGHTS_REQUIRED")
            val &= ~0x0F0000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "IoControlCode":
        val = int(arg_val, 16)
        return {
            0x1200B: "IOCTL_AFD_START_LISTEN",
            0x12010: "IOCTL_AFD_ACCEPT",
            0x1201B: "IOCTL_AFD_RECV_DATAGRAM",
            0x12024: "IOCTL_AFD_SELECT",
            0x12023: "IOCTL_AFD_SEND_DATAGRAM",
            0x1207B: "IOCTL_AFD_GET_INFO",
            0x1203B: "IOCTL_AFD_SET_INFO",
            0x12047: "IOCTL_AFD_SET_CONTEXT",
            0x12003: "IOCTL_AFD_BIND",
            0x12007: "IOCTL_AFD_CONNECT",
            0x1202B: "IOCTL_AFD_DISCONNECT",
            0x120BF: "IOCTL_AFD_DEFER_ACCEPT",
            0x12017: "IOCTL_AFD_RECV",
            0x1201F: "IOCTL_AFD_SEND",
            0x1202F: "IOCTL_AFD_GET_SOCK_NAME",
            0x12087: "IOCTL_AFD_EVENT_SELECT",
            0x1208B: "IOCTL_AFD_ENUM_NETWORK_EVENTS",
            0x24058: "IOCTL_CDROM_GET_CONFIGURATION",
            0x41018: "IOCTL_SCSI_GET_ADDRESS",
            0x4D008: "IOCTL_SCSI_MINIPORT",
            0x4D014: "IOCTL_SCSI_PASS_THROUGH_DIRECT",
            0x70000: "IOCTL_DISK_GET_DRIVE_GEOMETRY",
            0x70048: "IOCTL_DISK_GET_PARTITION_INFO_EX",
            0x70050: "IOCTL_DISK_GET_DRIVE_LAYOUT_EX",
            0x700A0: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
            0x7405C: "IOCTL_DISK_GET_LENGTH_INFO",
            0x740D4: "IOCTL_DISK_GET_CACHE_INFORMATION",
            0x90018: "FSCTL_LOCK_VOLUME",
            0x9001C: "FSCTL_UNLOCK_VOLUME",
            0x900A8: "FSCTL_GET_REPARSE_POINT",
            0x2D0C10: "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER",
            0x2D1080: "IOCTL_STORAGE_GET_DEVICE_NUMBER",
            0x2D1400: "IOCTL_STORAGE_QUERY_PROPERTY",
            0x398000: "IOCTL_KSEC_REGISTER_LSA_PROCESS",
            0x390004: "IOCTL_KSEC_1",
            0x390008: "IOCTL_KSEC_RANDOM_FILL_BUFFER",
            0x39000E: "IOCTL_KSEC_ENCRYPT_PROCESS",
            0x390012: "IOCTL_KSEC_DECRYPT_PROCESS",
            0x390016: "IOCTL_KSEC_ENCRYPT_CROSS_PROCESS",
            0x39001A: "IOCTL_KSEC_DECRYPT_CROSS_PROCESS",
            0x39001E: "IOCTL_KSEC_ENCRYPT_SAME_LOGON",
            0x390022: "IOCTL_KSEC_DECRYPT_SAME_LOGON",
            0x390038: "IOCTL_KSEC_REGISTER_EXTENSION",
            0x4D0008: "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME",
            0x560000: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
            0x6D0008: "IOCTL_MOUNTMGR_QUERY_POINTS",
            0x6D0030: "IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH",
            0x6D0034: "IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS",
        }.get(val, None)
    elif (
        arg_name == "Protection"
        or arg_name == "Win32Protect"
        or arg_name == "NewAccessProtection"
        or arg_name == "OldAccessProtection"
        or arg_name == "OldProtection"
    ):
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("PAGE_NOACCESS")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("PAGE_READONLY")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("PAGE_READWRITE")
            val &= ~0x00000004
        if val & 0x00000008:
            res.append("PAGE_WRITECOPY")
            val &= ~0x00000008
        if val & 0x00000010:
            res.append("PAGE_EXECUTE")
            val &= ~0x00000010
        if val & 0x00000020:
            res.append("PAGE_EXECUTE_READ")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("PAGE_EXECUTE_READWRITE")
            val &= ~0x00000040
        if val & 0x00000080:
            res.append("PAGE_EXECUTE_WRITECOPY")
            val &= ~0x00000080
        if val & 0x00000100:
            res.append("PAGE_GUARD")
            val &= ~0x00000100
        if val & 0x00000200:
            res.append("PAGE_NOCACHE")
            val &= ~0x00000200
        if val & 0x00000400:
            res.append("PAGE_WRITECOMBINE")
            val &= ~0x00000400
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name in ["CreateProcessInternalW", "CreateProcessWithTokenW", "CreateProcessWithLogonW"] and arg_name == "CreationFlags":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("DEBUG_PROCESS")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("DEBUG_ONLY_THIS_PROCESS")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("CREATE_SUSPENDED")
            val &= ~0x00000004
        if val & 0x00000008:
            res.append("DETACHED_PROCESS")
            val &= ~0x00000008
        if val & 0x00000010:
            res.append("CREATE_NEW_CONSOLE")
            val &= ~0x00000010
        if val & 0x00000020:
            res.append("NORMAL_PRIORITY_CLASS")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("IDLE_PRIORITY_CLASS")
            val &= ~0x00000040
        if val & 0x00000080:
            res.append("HIGH_PRIORITY_CLASS")
            val &= ~0x00000080
        if val & 0x00000400:
            res.append("CREATE_UNICODE_ENVIRONMENT")
            val &= ~0x00000400
        if val & 0x00040000:
            res.append("CREATE_PROTECTED_PROCESS")
            val &= ~0x00040000
        if val & 0x00080000:
            res.append("EXTENDED_STARTUPINFO_PRESENT")
            val &= ~0x00080000
        if val & 0x01000000:
            res.append("CREATE_BREAKAWAY_FROM_JOB")
            val &= ~0x01000000
        if val & 0x02000000:
            res.append("CREATE_PRESERVE_CODE_AUTHZ_LEVEL")
            val &= ~0x02000000
        if val & 0x04000000:
            res.append("CREATE_DEFAULT_ERROR_MODE")
            val &= ~0x04000000
        if val & 0x08000000:
            res.append("CREATE_NO_WINDOW")
            val &= ~0x08000000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif (api_name == "MoveFileWithProgressW" or api_name == "MoveFileWithProgressTransactedW") and arg_name == "Flags":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("MOVEFILE_REPLACE_EXISTING")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("MOVEFILE_COPY_ALLOWED")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("MOVEFILE_DELAY_UNTIL_REBOOT")
            val &= ~0x00000004
        if val & 0x00000008:
            res.append("MOVEFILE_WRITE_THROUGH")
            val &= ~0x00000008
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif arg_name == "FileAttributes":
        val = int(arg_val, 16)
        res = []
        if val == 0x00000080:
            return "FILE_ATTRIBUTE_NORMAL"
        if val & 0x00000001:
            res.append("FILE_ATTRIBUTE_READONLY")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("FILE_ATTRIBUTE_HIDDEN")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("FILE_ATTRIBUTE_SYSTEM")
            val &= ~0x00000004
        if val & 0x00000010:
            res.append("FILE_ATTRIBUTE_DIRECTORY")
            val &= ~0x00000010
        if val & 0x00000020:
            res.append("FILE_ATTRIBUTE_ARCHIVE")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("FILE_ATTRIBUTE_DEVICE")
            val &= ~0x00000040
        if val & 0x00000100:
            res.append("FILE_ATTRIBUTE_TEMPORARY")
            val &= ~0x00000100
        if val & 0x00000200:
            res.append("FILE_ATTRIBUTE_SPARSE_FILE")
            val &= ~0x00000200
        if val & 0x00000400:
            res.append("FILE_ATTRIBUTE_REPARSE_POINT")
            val &= ~0x00000400
        if val & 0x00000800:
            res.append("FILE_ATTRIBUTE_COMPRESSED")
            val &= ~0x00000800
        if val & 0x00001000:
            res.append("FILE_ATTRIBUTE_OFFLINE")
            val &= ~0x00001000
        if val & 0x00002000:
            res.append("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED")
            val &= ~0x00002000
        if val & 0x00004000:
            res.append("FILE_ATTRIBUTE_ENCRYPTED")
            val &= ~0x00004000
        if val & 0x00008000:
            res.append("FILE_ATTRIBUTE_VIRTUAL")
            val &= ~0x00008000
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif (
        api_name == "NtCreateFile" or api_name == "NtOpenFile" or api_name == "NtCreateDirectoryObject" or api_name == "NtOpenDirectoryObject"
    ) and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        remove = 0
        res = []
        if val & 0x80000000:
            res.append("GENERIC_READ")
            remove |= 0x80000000
        if val & 0x40000000:
            res.append("GENERIC_WRITE")
            remove |= 0x40000000
        if val & 0x20000000:
            res.append("GENERIC_EXECUTE")
            remove |= 0x20000000
        if val & 0x10000000:
            res.append("GENERIC_ALL")
            remove |= 0x10000000
        if val & 0x02000000:
            res.append("MAXIMUM_ALLOWED")
            remove |= 0x02000000
        if (val & 0x1F01FF) == 0x1F01FF:
            res.append("FILE_ALL_ACCESS")
            val &= ~0x1F01FF
        if (val & 0x120089) == 0x120089:
            res.append("FILE_GENERIC_READ")
            remove |= 0x120089
        if (val & 0x120116) == 0x120116:
            res.append("FILE_GENERIC_WRITE")
            remove |= 0x120116
        if (val & 0x1200A0) == 0x1200A0:
            res.append("FILE_GENERIC_EXECUTE")
            remove |= 0x1200A0
        val &= ~remove
        # for values 1 -> 0x20, these can have different meanings depending on whether
        # it's a file or a directory operated on -- choose file by default since
        # we don't have enough information to make an accurate determination
        if val & 0x00000001:
            res.append("FILE_READ_ACCESS")
            remove |= 0x00000001
        if val & 0x00000002:
            res.append("FILE_WRITE_ACCESS")
            remove |= 0x00000002
        if val & 0x00000004:
            res.append("FILE_APPEND_DATA")
            remove |= 0x00000004
        if val & 0x00000008:
            res.append("FILE_READ_EA")
            remove |= 0x00000008
        if val & 0x00000010:
            res.append("FILE_WRITE_EA")
            remove |= 0x00000010
        if val & 0x00000020:
            res.append("FILE_EXECUTE")
            remove |= 0x00000020
        if val & 0x00000040:
            res.append("FILE_DELETE_CHILD")
            remove |= 0x00000040
        if val & 0x00000080:
            res.append("FILE_READ_ATTRIBUTES")
            remove |= 0x00000080
        if val & 0x00000100:
            res.append("FILE_WRITE_ATTRIBUTES")
            remove |= 0x00000100
        if val & 0x00010000:
            res.append("DELETE")
            remove |= 0x00010000
        if val & 0x00020000:
            res.append("READ_CONTROL")
            remove |= 0x00020000
        if val & 0x00040000:
            res.append("WRITE_DAC")
            remove |= 0x00040000
        if val & 0x00080000:
            res.append("WRITE_OWNER")
            remove |= 0x00080000
        if val & 0x00100000:
            res.append("SYNCHRONIZE")
            remove |= 0x00100000
        if val & 0x01000000:
            res.append("ACCESS_SYSTEM_SECURITY")
            remove |= 0x01000000
        val &= ~remove
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "NtOpenProcess" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        remove = 0
        res = []
        if val & 0x80000000:
            res.append("GENERIC_READ")
            remove |= 0x80000000
        if val & 0x40000000:
            res.append("GENERIC_WRITE")
            remove |= 0x40000000
        if val & 0x20000000:
            res.append("GENERIC_EXECUTE")
            remove |= 0x20000000
        if val & 0x10000000:
            res.append("GENERIC_ALL")
            remove |= 0x10000000
        if val & 0x02000000:
            res.append("MAXIMUM_ALLOWED")
            remove |= 0x02000000
        # for >= vista
        if (val & 0x1FFFFF) == 0x1FFFFF:
            res.append("PROCESS_ALL_ACCESS")
            val &= ~0x1FFFFF
        # for < vista
        if (val & 0x1F0FFF) == 0x1F0FFF:
            res.append("PROCESS_ALL_ACCESS")
            val &= ~0x1F0FFF
        val &= ~remove
        if val & 0x0001:
            res.append("PROCESS_TERMINATE")
            remove |= 0x0001
        if val & 0x0002:
            res.append("PROCESS_CREATE_THREAD")
            remove |= 0x0002
        if val & 0x0004:
            res.append("PROCESS_SET_SESSIONID")
            remove |= 0x0004
        if val & 0x0008:
            res.append("PROCESS_VM_OPERATION")
            remove |= 0x0008
        if val & 0x0010:
            res.append("PROCESS_VM_READ")
            remove |= 0x0010
        if val & 0x0020:
            res.append("PROCESS_VM_WRITE")
            remove |= 0x0020
        if val & 0x0040:
            res.append("PROCESS_DUP_HANDLE")
            remove |= 0x0040
        if val & 0x0080:
            res.append("PROCESS_CREATE_PROCESS")
            remove |= 0x0080
        if val & 0x0100:
            res.append("PROCESS_SET_QUOTA")
            remove |= 0x0100
        if val & 0x0200:
            res.append("PROCESS_SET_INFORMATION")
            remove |= 0x0200
        if val & 0x0400:
            res.append("PROCESS_QUERY_INFORMATION")
            remove |= 0x0400
        if val & 0x0800:
            res.append("PROCESS_SUSPEND_RESUME")
            remove |= 0x0800
        if val & 0x1000:
            res.append("PROCESS_QUERY_LIMITED_INFORMATION")
            remove |= 0x1000
        if val & 0x100000:
            res.append("SYNCHRONIZE")
            remove |= 0x100000
        val &= ~remove
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "NtOpenThread" and arg_name == "DesiredAccess":
        val = int(arg_val, 16)
        remove = 0
        res = []
        if val & 0x80000000:
            res.append("GENERIC_READ")
            remove |= 0x80000000
        if val & 0x40000000:
            res.append("GENERIC_WRITE")
            remove |= 0x40000000
        if val & 0x20000000:
            res.append("GENERIC_EXECUTE")
            remove |= 0x20000000
        if val & 0x10000000:
            res.append("GENERIC_ALL")
            remove |= 0x10000000
        if val & 0x02000000:
            res.append("MAXIMUM_ALLOWED")
            remove |= 0x02000000
        # for >= vista
        if (val & 0x1FFFFF) == 0x1FFFFF:
            res.append("THREAD_ALL_ACCESS")
            val &= ~0x1FFFFF
        # for < vista
        if (val & 0x1F03FF) == 0x1F03FF:
            res.append("THREAD_ALL_ACCESS")
            val &= ~0x1F03FF
        val &= ~remove
        if val & 0x0001:
            res.append("THREAD_TERMINATE")
            remove |= 0x0001
        if val & 0x0002:
            res.append("THREAD_SUSPEND_RESUME")
            remove |= 0x0002
        if val & 0x0008:
            res.append("THREAD_GET_CONTEXT")
            remove |= 0x0008
        if val & 0x0010:
            res.append("THREAD_SET_CONTEXT")
            remove |= 0x0010
        if val & 0x0020:
            res.append("THREAD_SET_INFORMATION")
            remove |= 0x0020
        if val & 0x0040:
            res.append("THREAD_QUERY_INFORMATION")
            remove |= 0x0040
        if val & 0x0080:
            res.append("THREAD_SET_THREAD_TOKEN")
            remove |= 0x0080
        if val & 0x0100:
            res.append("THREAD_IMPERSONATE")
            remove |= 0x0100
        if val & 0x0200:
            res.append("THREAD_DIRECT_IMPERSONATION")
            remove |= 0x0200
        if val & 0x0400:
            res.append("THREAD_SET_LIMITED_INFORMATION")
            remove |= 0x0400
        if val & 0x0800:
            res.append("THREAD_QUERY_LIMITED_INFORMATION")
            remove |= 0x0800
        val &= ~remove
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "CoInternetSetFeatureEnabled" and arg_name == "FeatureEntry":
        val = int(arg_val, 10)
        return {
            0: "FEATURE_OBJECT_CACHING",
            1: "FEATURE_ZONE_ELEVATION",
            2: "FEATURE_MIME_HANDLING",
            3: "FEATURE_MIME_SNIFFING",
            4: "FEATURE_WINDOW_RESTRICTIONS",
            5: "FEATURE_WEBOC_POPUPMANAGEMENT",
            6: "FEATURE_BEHAVIORS",
            7: "FEATURE_DISABLE_MK_PROTOCOL",
            8: "FEATURE_LOCALMACHINE_LOCKDOWN",
            9: "FEATURE_SECURITYBAND",
            10: "FEATURE_RESTRICT_ACTIVEXINSTALL",
            11: "FEATURE_VALIDATE_NAVIGATE_URL",
            12: "FEATURE_RESTRICT_FILEDOWNLOAD",
            13: "FEATURE_ADDON_MANAGEMENT",
            14: "FEATURE_PROTOCOL_LOCKDOWN",
            15: "FEATURE_HTTP_USERNAME_PASSWORD_DISABLE",
            16: "FEATURE_SAFE_BINDTOOBJECT",
            17: "FEATURE_UNC_SAVEDFILECHECK",
            18: "FEATURE_GET_URL_DOM_FILEPATH_UNENCODED",
            19: "FEATURE_TABBED_BROWSING",
            20: "FEATURE_SSLUX",
            21: "FEATURE_DISABLE_NAVIGATION_SOUNDS",
            22: "FEATURE_DISABLE_LEGACY_COMPRESSION",
            23: "FEATURE_FORCE_ADDR_AND_STATUS",
            24: "FEATURE_XMLHTTP",
            25: "FEATURE_DISABLE_TELNET_PROTOCOL",
            26: "FEATURE_FEEDS",
            27: "FEATURE_BLOCK_INPUT_PROMPTS",
        }.get(val, None)
    elif api_name == "CoInternetSetFeatureEnabled" and arg_name == "Flags":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("SET_FEATURE_ON_THREAD")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("SET_FEATURE_ON_PROCESS")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("SET_FEATURE_IN_REGISTRY")
            val &= ~0x00000004
        if val & 0x00000008:
            res.append("SET_FEATURE_ON_THREAD_LOCALMACHINE")
            val &= ~0x00000008
        if val & 0x00000010:
            res.append("SET_FEATURE_ON_THREAD_INTRANET")
            val &= ~0x00000010
        if val & 0x00000020:
            res.append("SET_FEATURE_ON_THREAD_TRUSTED")
            val &= ~0x00000020
        if val & 0x00000040:
            res.append("SET_FEATURE_ON_THREAD_INTERNET")
            val &= ~0x00000040
        if val & 0x00000080:
            res.append("SET_FEATURE_ON_THREAD_RESTRICTED")
            val &= ~0x00000080
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "NtDuplicateObject" and arg_name == "Options":
        val = int(arg_val, 16)
        res = []
        if val & 0x00000001:
            res.append("DUPLICATE_CLOSE_SOURCE")
            val &= ~0x00000001
        if val & 0x00000002:
            res.append("DUPLICATE_SAME_ACCESS")
            val &= ~0x00000002
        if val & 0x00000004:
            res.append("DUPLICATE_SAME_ATTRIBUTES")
            val &= ~0x00000004
        if val:
            res.append("0x{0:08x}".format(val))
        return "|".join(res)
    elif api_name == "InternetSetOptionA" and arg_name == "Option":
        val = int(arg_val, 16)
        return {
            1: "INTERNET_OPTION_CALLBACK",
            2: "INTERNET_OPTION_CONNECT_TIMEOUT",
            3: "INTERNET_OPTION_CONNECT_RETRIES",
            4: "INTERNET_OPTION_CONNECT_BACKOFF",
            5: "INTERNET_OPTION_SEND_TIMEOUT",
            6: "INTERNET_OPTION_RECEIVE_TIMEOUT",
            7: "INTERNET_OPTION_DATA_SEND_TIMEOUT",
            8: "INTERNET_OPTION_DATA_RECEIVE_TIMEOUT",
            9: "INTERNET_OPTION_HANDLE_TYPE",
            11: "INTERNET_OPTION_LISTEN_TIMEOUT",
            12: "INTERNET_OPTION_READ_BUFFER_SIZE",
            13: "INTERNET_OPTION_WRITE_BUFFER_SIZE",
            15: "INTERNET_OPTION_ASYNC_ID",
            16: "INTERNET_OPTION_ASYNC_PRIORITY",
            21: "INTERNET_OPTION_PARENT_HANDLE",
            22: "INTERNET_OPTION_KEEP_CONNECTION",
            23: "INTERNET_OPTION_REQUEST_FLAGS",
            24: "INTERNET_OPTION_EXTENDED_ERROR",
            26: "INTERNET_OPTION_OFFLINE_MODE",
            27: "INTERNET_OPTION_CACHE_STREAM_HANDLE",
            28: "INTERNET_OPTION_USERNAME",
            29: "INTERNET_OPTION_PASSWORD",
            30: "INTERNET_OPTION_ASYNC",
            31: "INTERNET_OPTION_SECURITY_FLAGS",
            32: "INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT",
            33: "INTERNET_OPTION_DATAFILE_NAME",
            34: "INTERNET_OPTION_URL",
            35: "INTERNET_OPTION_SECURITY_CERTIFICATE",
            36: "INTERNET_OPTION_SECURITY_KEY_BITNESS",
            37: "INTERNET_OPTION_REFRESH",
            38: "INTERNET_OPTION_PROXY",
            39: "INTERNET_OPTION_SETTINGS_CHANGED",
            40: "INTERNET_OPTION_VERSION",
            41: "INTERNET_OPTION_USER_AGENT",
            42: "INTERNET_OPTION_END_BROWSER_SESSION",
            43: "INTERNET_OPTION_PROXY_USERNAME",
            44: "INTERNET_OPTION_PROXY_PASSWORD",
            45: "INTERNET_OPTION_CONTEXT_VALUE",
            46: "INTERNET_OPTION_CONNECT_LIMIT",
            47: "INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT",
            48: "INTERNET_OPTION_POLICY",
            49: "INTERNET_OPTION_DISCONNECTED_TIMEOUT",
            50: "INTERNET_OPTION_CONNECTED_STATE",
            51: "INTERNET_OPTION_IDLE_STATE",
            52: "INTERNET_OPTION_OFFLINE_SEMANTICS",
            53: "INTERNET_OPTION_SECONDARY_CACHE_KEY",
            54: "INTERNET_OPTION_CALLBACK_FILTER",
            55: "INTERNET_OPTION_CONNECT_TIME",
            56: "INTERNET_OPTION_SEND_THROUGHPUT",
            57: "INTERNET_OPTION_RECEIVE_THROUGHPUT",
            58: "INTERNET_OPTION_REQUEST_PRIORITY",
            59: "INTERNET_OPTION_HTTP_VERSION",
            60: "INTERNET_OPTION_RESET_URLCACHE_SESSION",
            62: "INTERNET_OPTION_ERROR_MASK",
            63: "INTERNET_OPTION_FROM_CACHE_TIMEOUT",
            64: "INTERNET_OPTION_BYPASS_EDITED_ENTRY",
            65: "INTERNET_OPTION_HTTP_DECODING",
            67: "INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO",
            68: "INTERNET_OPTION_CODEPAGE",
            69: "INTERNET_OPTION_CACHE_TIMESTAMPS",
            70: "INTERNET_OPTION_DISABLE_AUTODIAL",
            73: "INTERNET_OPTION_MAX_CONNS_PER_SERVER",
            74: "INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER",
            75: "INTERNET_OPTION_PER_CONNECTION_OPTION",
            76: "INTERNET_OPTION_DIGEST_AUTH_UNLOAD",
            77: "INTERNET_OPTION_IGNORE_OFFLINE",
            78: "INTERNET_OPTION_IDENTITY",
            79: "INTERNET_OPTION_REMOVE_IDENTITY",
            80: "INTERNET_OPTION_ALTER_IDENTITY",
            81: "INTERNET_OPTION_SUPPRESS_BEHAVIOR",
            82: "INTERNET_OPTION_AUTODIAL_MODE",
            83: "INTERNET_OPTION_AUTODIAL_CONNECTION",
            84: "INTERNET_OPTION_CLIENT_CERT_CONTEXT",
            85: "INTERNET_OPTION_AUTH_FLAGS",
            86: "INTERNET_OPTION_COOKIES_3RD_PARTY",
            87: "INTERNET_OPTION_DISABLE_PASSPORT_AUTH",
            88: "INTERNET_OPTION_SEND_UTF8_SERVERNAME_TO_PROXY",
            89: "INTERNET_OPTION_EXEMPT_CONNECTION_LIMIT",
            90: "INTERNET_OPTION_ENABLE_PASSPORT_AUTH",
            91: "INTERNET_OPTION_HIBERNATE_INACTIVE_WORKER_THREADS",
            92: "INTERNET_OPTION_ACTIVATE_WORKER_THREADS",
            93: "INTERNET_OPTION_RESTORE_WORKER_THREAD_DEFAULTS",
            94: "INTERNET_OPTION_SOCKET_SEND_BUFFER_LENGTH",
            95: "INTERNET_OPTION_PROXY_SETTINGS_CHANGED",
            96: "INTERNET_OPTION_DATAFILE_EXT",
            100: "INTERNET_OPTION_CODEPAGE_PATH",
            101: "INTERNET_OPTION_CODEPAGE_EXTRA",
            102: "INTERNET_OPTION_IDN",
            103: "INTERNET_OPTION_MAX_CONNS_PER_PROXY",
            104: "INTERNET_OPTION_SUPPRESS_SERVER_AUTH",
            105: "INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT",
        }.get(val, None)
    elif api_name in ["socket", "WSASocketA", "WSASocketW"]:
        if arg_name == "af":
            val = int(arg_val, 10)
            return {
                0: "AF_UNSPEC",
                2: "AF_INET",
                6: "AF_IPX",
                16: "AF_APPLETALK",
                17: "AF_NETBIOS",
                23: "AF_INET6",
                26: "AF_IRDA",
                32: "AF_BTH",
            }.get(val, None)
        elif arg_name == "type":
            val = int(arg_val, 10)
            return {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM", 5: "SOCK_SEQPACKET",}.get(val, None)
        elif arg_name == "protocol":
            val = int(arg_val, 10)
            return {
                1: "IPPROTO_ICMP",
                2: "IPPROTO_IGMP",
                3: "BTHPROTO_RFCOMM",
                6: "IPPROTO_TCP",
                17: "IPPROTO_UDP",
                58: "IPPROTO_ICMPV6",
                113: "IPPROTO_RM",
            }.get(val, None)
    elif arg_name == "FileInformationClass":
        val = int(arg_val, 10)
        return {
            1: "FileDirectoryInformation",
            2: "FileFullDirectoryInformation",
            3: "FileBothDirectoryInformation",
            4: "FileBasicInformation",
            5: "FileStandardInformation",
            6: "FileInternalInformation",
            7: "FileEaInformation",
            8: "FileAccessInformation",
            9: "FileNameInformation",
            10: "FileRenameInformation",
            11: "FileLinkInformation",
            12: "FileNamesInformation",
            13: "FileDispositionInformation",
            14: "FilePositionInformation",
            15: "FileFullEaInformation",
            16: "FileModeInformation",
            17: "FileAlignmentInformation",
            18: "FileAllInformation",
            19: "FileAllocationInformation",
            20: "FileEndOfFileInformation",
            21: "FileAlternativeNameInformation",
            22: "FileStreamInformation",
            23: "FilePipeInformation",
            24: "FilePipeLocalInformation",
            25: "FilePipeRemoteInformation",
            26: "FileMailslotQueryInformation",
            27: "FileMailslotSetInformation",
            28: "FileCompressionInformation",
            29: "FileObjectIdInformation",
            30: "FileCompletionInformation",
            31: "FileMoveClusterInformation",
            32: "FileQuotaInformation",
            33: "FileReparsePointInformation",
            34: "FileNetworkOpenInformation",
            35: "FileAttributeTagInformation",
            36: "FileTrackingInformation",
            37: "FileIdBothDirectoryInformation",
            38: "FileIdFullDirectoryInformation",
            39: "FileShortNameInformation",
            40: "FileIoCompletionNotificationInformation",
            41: "FileIoStatusBlockRangeInformation",
            42: "FileIoPriorityHintInformation",
            43: "FileSfioReserveInformation",
            44: "FileSfioVolumeInformation",
            45: "FileHardLinkInformation",
            46: "FileProcessIdsUsingFileInformation",
            47: "FileNormalizedNameInformation",
            48: "FileNetworkPhysicalNameInformation",
            49: "FileIdGlobalTxDirectoryInformation",
            50: "FileIsRemoteDeviceInformation",
            51: "FileAttributeCacheInformation",
            52: "FileNumaNodeInformation",
            53: "FileStandardLinkInformation",
            54: "FileRemoteProtocolInformation",
            55: "FileReplaceCompletionInformation",
            56: "FileMaximumInformation",
        }.get(val, None)
    elif arg_name == "ProcessInformationClass":
        val = int(arg_val, 10)
        return {
            0: "ProcessBasicInformation",
            7: "ProcessDebugPort",
            29: "ProcessBreakOnTermination",
            30: "ProcessDebugObjectHandle",
            31: "ProcessDebugFlags",
            34: "ProcessExecuteFlags",
        }.get(val, None)
    elif arg_name == "ThreadInformationClass":
        val = int(arg_val, 10)
        return {0: "ThreadBasicInformation", 17: "ThreadHideFromDebugger",}.get(val, None)
    elif arg_name == "MemType":
        val = int(arg_val, 16)
        return {0x20000: "MEM_PRIVATE", 0x40000: "MEM_MAPPED", 0x1000000: "MEM_IMAGE",}.get(val, None)
    elif arg_name == "Show":
        val = int(arg_val, 10)
        return {
            0: "SW_HIDE",
            1: "SW_SHOWNORMAL",
            2: "SW_SHOWMINIMIZED",
            3: "SW_SHOWMAXIMIZED",
            4: "SW_SHOWNOACTIVATE",
            5: "SW_SHOW",
            6: "SW_MINIMIZE",
            7: "SW_SHOWMINNOACTIVE",
            8: "SW_SHOWNA",
            9: "SW_RESTORE",
            10: "SW_SHOWDEFAULT",
            11: "SW_FORCEMINIMIZE",
        }.get(val, None)
    elif arg_name == "Registry":
        val = int(arg_val, 16)
        return {
            0x80000000: "HKEY_CLASSES_ROOT",
            0x80000001: "HKEY_CURRENT_USER",
            0x80000002: "HKEY_LOCAL_MACHINE",
            0x80000003: "HKEY_USERS",
            0x80000004: "HKEY_PERFORMANCE_DATA",
            0x80000005: "HKEY_CURRENT_CONFIG",
            0x80000006: "HKEY_DYN_DATA",
        }.get(val, None)

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
    out = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(random.randint(5, 15)))
    return out

MAX_FILENAME_LEN = 24

def truncate_filename(x):
    truncated = None
    parts = x.rsplit('.',1)
    if len(parts) > 1:
        # filename has extension
        extension  = parts[1]
        name = parts[0][:(MAX_FILENAME_LEN-(len(extension)+1))]
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
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname[:15]))[20:24])  # SIOCGIFADDR
