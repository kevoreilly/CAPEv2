# Copyright (C) 2020 Kevin O'Reilly.
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

import logging
from ctypes import byref, sizeof

from lib.api.process import Process
from lib.common.abstracts import Auxiliary
from lib.common.defines import KERNEL32, PROCESSENTRY32, TH32CS_SNAPPROCESS
from lib.common.exceptions import CuckooError

log = logging.getLogger(__name__)


class TLSDumpMasterSecrets(Auxiliary):
    """Dump TLS master secrets from lsass process"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.config = config
        self.enabled = self.config.tlsdump
        if self.enabled:
            self.options["tlsdump"] = "1"
        else:
            self.options["tlsdump"] = "0"

    def start(self):
        proc_info = PROCESSENTRY32()
        proc_info.dwSize = sizeof(PROCESSENTRY32)
        snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        flag = KERNEL32.Process32First(snapshot, byref(proc_info))
        pid = 0
        while flag:
            if proc_info.sz_exeFile == b"lsass.exe":
                pid = proc_info.th32ProcessID
                log.info("lsass.exe found, pid %d", pid)
                flag = 0
            flag = KERNEL32.Process32Next(snapshot, byref(proc_info))
        if not pid:
            log.warning("Unable to find lsass.exe process")
            return
        try:
            p = Process(options=self.options, config=self.config, pid=pid)
            filepath = p.get_filepath()
            p.inject(interest=filepath, nosleepskip=True)
        except CuckooError as e:
            if "process access denied" in e.message:
                log.warning("You're not running the Agent as Administrator")
            else:
                log.warning(
                    "An unknown error occurred while trying to inject into the lsass.exe process to dump TLS master secrets: %s",
                    e,
                )
        del self.options["tlsdump"]
