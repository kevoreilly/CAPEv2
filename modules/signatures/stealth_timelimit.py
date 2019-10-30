# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthTimeout(Signature):
    name = "stealth_timeout"
    description = "Possible date expiration check, exits too soon after checking local time"
    severity = 2
    confidence = 50
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.systimeidx = 0
        self.getsystimeidx = 0
        self.exitidx = 0
        self.curidx = 0

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.lastprocess = process
            self.systimeidx = 0
            self.exitidx = 0
            self.curidx = 0

        self.curidx += 1

        if call["api"] == "GetSystemTimeAsFileTime":
            self.systimeidx = self.curidx
            self.getsystimeidx = self.curidx
        elif call["api"] == "GetSystemTime" or call["api"] == "GetLocalTime" or call["api"] == "NtQuerySystemTime":
            self.systimeidx = self.curidx
        elif call["api"] == "NtDelayExecution" or call["api"] == "NtWaitForSingleObject":
            # If we see a sleep sequence, invalidate it as a time check
            if self.curidx == self.getsystimeidx + 1:
                self.systimeidx = 0
        elif call["api"] == "NtTerminateProcess":
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" or handle == "0x00000000":
                self.exitidx = self.curidx
                if self.systimeidx and self.exitidx and self.systimeidx > (self.exitidx - 10):
                    if process["module_path"].lower() != "c:\\windows\\system32\\attrib.exe":
                        self.data.append({"process" : process["process_name"] + ", PID " + str(process["process_id"])})
                        return True

        return None

