# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class InjectionRWX(Signature):
    name = "injection_rwx"
    description = "Creates RWX memory"
    severity = 2
    confidence = 50
    categories = ["injection"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1055"]  # MITRE v6,7,8
    mbcs = ["OB0006", "OB0013", "E1055"]

    filter_apinames = set(["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "VirtualProtectEx"])
    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.dont_check = False

        if self.results["info"]["package"] not in ["exe", "rar", "zip", "dll", "regsvr"]:
            self.dont_check = True

    def on_call(self, call, process):
        if self.dont_check:
            return False

        if call["api"] == "NtAllocateVirtualMemory" or call["api"] == "VirtualProtectEx":
            protection = self.get_argument(call, "Protection")
            # PAGE_EXECUTE_READWRITE
            if protection == "0x00000040":
                if self.pid:
                    self.mark_call()
                return True
        elif call["api"] == "NtProtectVirtualMemory":
            protection = self.get_argument(call, "NewAccessProtection")
            # PAGE_EXECUTE_READWRITE
            if protection == "0x00000040":
                if self.pid:
                    self.mark_call()
                return True
