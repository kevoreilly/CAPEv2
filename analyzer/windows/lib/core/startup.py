# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import ctypes
import logging
import os
from datetime import datetime

from lib.common.constants import PATHS
from lib.common.defines import KERNEL32, SYSTEMTIME
from lib.common.results import NetlogHandler

log = logging.getLogger()


def create_folders():
    """Create folders in PATHS."""
    for name, folder in PATHS.items():
        if os.path.exists(folder):
            continue

        with contextlib.suppress(OSError):
            os.makedirs(folder)


def init_logging():
    """Initialize logger."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)

    global netlog_handler
    netlog_handler = NetlogHandler()
    netlog_handler.setFormatter(formatter)
    log.addHandler(netlog_handler)

    log.setLevel(logging.DEBUG)


def disconnect_logger():
    """Cleanly close the logger. Note that LogHandler also implements close."""
    netlog_handler.close()


def set_clock(clock, timeout):
    # Output key info to analysis log
    log.info("Date set to: %s, timeout set to: %s", clock, timeout)

    clock = datetime.strptime(clock, "%Y%m%dT%H:%M:%S")
    st = SYSTEMTIME()
    st.wYear = clock.year
    st.wMonth = clock.month
    st.wDay = clock.day
    st.wHour = clock.hour
    st.wMinute = clock.minute
    st.wSecond = clock.second
    st.wMilliseconds = 0
    KERNEL32.SetLocalTime(ctypes.byref(st))
