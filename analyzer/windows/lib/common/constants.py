# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.rand import random_string

ROOT = os.path.join(os.getenv("SystemDrive"), "\\", random_string(6, 10))

PATHS = {
    "root": ROOT,
    "logs": os.path.join(ROOT, "logs"),
    "files": os.path.join(ROOT, "files"),
    "shots": os.path.join(ROOT, "shots"),
    "memory": os.path.join(ROOT, "memory"),
    "drop": os.path.join(ROOT, "drop"),
}

PIPE = f"\\\\.\\PIPE\\{random_string(6, 10)}"
SHUTDOWN_MUTEX = f"Global\\{random_string(6, 10)}"
TERMINATE_EVENT = f"Global\\{random_string(6, 10)}"
CAPEMON32_NAME = f"dll\\{random_string(6, 8)}.dll"
CAPEMON64_NAME = f"dll\\{random_string(6, 8)}.dll"
LOADER32_NAME = f"bin\\{random_string(7)}.exe"
LOADER64_NAME = f"bin\\{random_string(8)}.exe"
LOGSERVER_PREFIX = f"\\\\.\\PIPE\\{random_string(8, 12)}"

# Options
OPT_APPDATA = "appdata"
OPT_ARGUMENTS = "arguments"
OPT_CLASS = "class"
OPT_CURDIR = "curdir"
OPT_DLLLOADER = "dllloader"
OPT_EXECUTIONDIR = "executiondir"
OPT_FILE = "file"
OPT_FREE = "free"
OPT_FUNCTION = "function"
OPT_KERNEL_ANALYSIS = "kernel_analysis"
OPT_INJECTION = "injection"
OPT_MULTI_PASSWORD = "enable_multi_password"
OPT_OFFSET = "offset"
OPT_PASSWORD = "password"
OPT_PROCDUMP = "procdump"
OPT_SERVICENAME = "servicename"
OPT_SERVICEDESC = "servicedesc"
OPT_RUNASX86 = "runasx86"
OPT_UNPACKER = "unpacker"

ARCHIVE_OPTIONS = (OPT_FILE, OPT_PASSWORD)
DLL_OPTIONS = (OPT_ARGUMENTS, OPT_DLLLOADER, OPT_FUNCTION)


""" Excel, Word, and Powerpoint won't have macros enabled without interaction for
documents that are outside one of its "Trusted Locations". Unless the user has
provided a 'curdir' option, use MSOFFICE_TRUSTED_PATH as the directory where
the document will be saved and executed from since that is a default trusted
location for all 3 apps. See
https://learn.microsoft.com/en-us/deployoffice/security/trusted-locations
"""
MSOFFICE_TRUSTED_PATH = os.path.join("%SystemDrive%", "Program Files", "Microsoft Office", "root", "Templates")
TRUSTED_PATH_TEXT = (
    f"Use MS Office Trusted Path location {MSOFFICE_TRUSTED_PATH} unless the user has provided a '{OPT_CURDIR}' option."
)
