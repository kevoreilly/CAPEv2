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
