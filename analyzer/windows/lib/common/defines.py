# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
from ctypes import (
    POINTER,
    Structure,
    Union,
    c_bool,
    c_char,
    c_double,
    c_int,
    c_ubyte,
    c_uint,
    c_ulonglong,
    c_ushort,
    c_void_p,
    c_wchar_p,
)

if sys.platform == "win32":
    from ctypes import WINFUNCTYPE, windll

    NTDLL = windll.ntdll
    KERNEL32 = windll.kernel32
    ADVAPI32 = windll.advapi32
    USER32 = windll.user32
    SHELL32 = windll.shell32
    PDH = windll.pdh
    PSAPI = windll.psapi
    EnumWindowsProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))
    EnumChildProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))

BYTE = c_ubyte
USHORT = c_ushort
WORD = c_ushort
DWORD = c_uint
DWORDLONG = c_ulonglong
LONG = c_int
ULONG = c_uint
UINT64 = c_ulonglong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
PWSTR = c_wchar_p
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_void_p
ULONG_PTR = c_void_p
SIZE_T = c_void_p
HMODULE = c_void_p
PWCHAR = c_wchar_p
DOUBLE = c_double

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
CREATE_SUSPENDED = 0x00000004
DBG_CONTINUE = 0x00010002
INFINITE = 0xFFFFFFFF
PROCESS_ALL_ACCESS = 0x001F0FFF
THREAD_ALL_ACCESS = 0x001F03FF
TOKEN_ALL_ACCESS = 0x000F01FF
PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
SE_PRIVILEGE_ENABLED = 0x00000002
STILL_ACTIVE = 0x00000103

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_DECOMMIT = 0x00004000
MEM_RELEASE = 0x00008000
MEM_RESET = 0x00080000

MEM_IMAGE = 0x01000000
MEM_MAPPED = 0x00040000
MEM_PRIVATE = 0x00020000

PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_ACCESS_INBOUND = 0x00000001
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 0x000000FF
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
FILE_FLAG_WRITE_THROUGH = 0x80000000
INVALID_HANDLE_VALUE = 0xFFFFFFFF
ERROR_BROKEN_PIPE = 0x0000006D
ERROR_MORE_DATA = 0x000000EA
ERROR_PIPE_CONNECTED = 0x00000217
ERROR_INVALID_HANDLE = 0x00000006

WAIT_TIMEOUT = 0x00000102

EVENT_MODIFY_STATE = 0x00000002

FILE_ATTRIBUTE_HIDDEN = 0x00000002

WM_GETTEXT = 0x0000000D
WM_GETTEXTLENGTH = 0x0000000E
WM_CLOSE = 0x00000010
BM_CLICK = 0x000000F5

SHARD_PATHA = 0x00000002

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000

OPEN_EXISTING = 0x00000003

TH32CS_SNAPPROCESS = 0x02

GMEM_MOVEABLE = 0x0002
CF_TEXT = 0x0001

PDH_FMT_DOUBLE = 0x00000200

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5
CREATE_NO_WINDOW = 0x08000000

MAX_PATH = 260

# Button messages
BM_SETCHECK = 0x000000F1
BM_GETCHECK = 0x000000F0
# Button states
BST_UNCHECKED = 0x0000
BST_CHECKED = 0x0001
BST_INDETERMINATE = 0x0002

# Process cannot access the file because it is being used by another process.
ERROR_SHARING_VIOLATION = 0x00000020


class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", DWORD),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", DWORD),
        ("dwFlags", DWORD),
        ("sz_exeFile", c_char * 260),
    ]


class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]


class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


class UNICODE_STRING(Structure):
    _pack_ = 1
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", PWCHAR),
    ]


class SECURITY_DESCRIPTOR(Structure):
    _pack_ = 1
    _fields_ = [
        ("Revision", BYTE),
        ("Sbz1", BYTE),
        ("Control", USHORT),
        ("Owner", PVOID),
        ("Group", PVOID),
        ("Sacl", PVOID),
        ("Dacl", PVOID),
    ]


class SECURITY_ATTRIBUTES(Structure):
    _pack_ = 1
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", PVOID),
        ("bInheritHandle", BYTE),
    ]


class SYSTEMTIME(Structure):
    _pack_ = 1
    _fields_ = [
        ("wYear", WORD),
        ("wMonth", WORD),
        ("wDayOfWeek", WORD),
        ("wDay", WORD),
        ("wHour", WORD),
        ("wMinute", WORD),
        ("wSecond", WORD),
        ("wMilliseconds", WORD),
    ]


class MEMORYSTATUSEX(Structure):
    _fields_ = [
        ("dwLength", DWORD),
        ("dwMemoryLoad", DWORD),
        ("ullTotalPhys", DWORDLONG),
        ("ullAvailPhys", DWORDLONG),
        ("ullTotalPageFile", DWORDLONG),
        ("ullAvailPageFile", DWORDLONG),
        ("ullTotalVirtual", DWORDLONG),
        ("ullAvailVirtual", DWORDLONG),
        ("ullAvailExtendedVirtual", DWORDLONG),
    ]


class PDH_FMT_COUNTERVALUE(Structure):
    _fields_ = [
        ("CStatus", DWORD),
        ("doubleValue", DOUBLE),
    ]
