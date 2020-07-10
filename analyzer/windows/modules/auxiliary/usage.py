# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from ctypes import *
import logging
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import PDH, KERNEL32, PVOID, DWORD, MEMORYSTATUSEX, PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)


class Usage(Auxiliary, Thread):
    """Collect CPU/memory usage info from monitored processes"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = True
        self.pidlist = []

    def stop(self):
        """Stop collecting usage info"""
        self.do_run = False

    def add_pid(self, pid):
        self.pidlist.append(pid)

    def del_pid(self, pid):
        if pid in self.pidlist:
            self.pidlist.remove(pid)

    def run(self):
        """Run capturing of usage info.
        @return: operation status.
        """

        meminfo = MEMORYSTATUSEX()
        meminfo.dwLength = sizeof(MEMORYSTATUSEX)

        phquery = PVOID()
        PDH.PdhOpenQuery(None, None, byref(phquery))
        buflen = DWORD()
        buflen.value = 0
        PDH.PdhExpandWildCardPathA(None, "\\Processor(*)\\% Processor Time", None, byref(buflen), 0)
        buf = create_string_buffer(buflen.value + 1)
        PDH.PdhExpandWildCardPathA(None, "\\Processor(*)\\% Processor Time", buf, byref(buflen), 0)
        counters = buf.raw.rstrip(b"\x00").split(b"\x00")
        counter_handles = []
        for counter in counters:
            if b"_Total" in counter:
                continue
            phcounter = PVOID()
            PDH.PdhAddCounterA(phquery, counter, None, byref(phcounter))
            counter_handles.append(phcounter)

        nf = NetlogFile()
        nf.init("aux/usage.log")

        PDH.PdhCollectQueryData(phquery)

        while self.do_run:
            time.sleep(2)
            PDH.PdhCollectQueryData(phquery)
            usage = PDH_FMT_COUNTERVALUE()
            bigfloat = 0.0
            for counter_handle in counter_handles:
                PDH.PdhGetFormattedCounterValue(counter_handle, PDH_FMT_DOUBLE, None, byref(usage))
                if usage.doubleValue > bigfloat:
                    bigfloat = usage.doubleValue

            KERNEL32.GlobalMemoryStatusEx(byref(meminfo))
            usagedata = b"%d %d\n" % (meminfo.dwMemoryLoad, round(bigfloat))
            nf.send(usagedata)

        for counter_handle in counter_handles:
            PDH.PdhRemoveCounter(counter_handle)
        PDH.PdhCloseQuery(phquery)

        nf.close()

        return True
