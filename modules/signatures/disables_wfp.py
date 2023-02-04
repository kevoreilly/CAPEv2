# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesWFP(Signature):
    name = "disables_wfp"
    description = "Attempts to disable Windows File Protection"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1562", "T1562.001"]  # MITRE v7,8
    mbcs = ["OB0006", "F0004", "F0004.007"]

    filter_apinames = set(["NtWriteFile", "CopyFileA", "CopyFileW", "CopyFileExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.saw_disable = False
        self.nextopen = None

    def on_call(self, call, process):
        if call["api"] == "NtWriteFile":
            filename = self.get_argument(call, "HandleName")
            filenamelower = filename.lower()
            if not self.saw_disable:
                if filenamelower.endswith("pipe\\sfcapi"):
                    self.saw_disable = True
                    if self.pid:
                        self.mark_call()
            elif not self.nextopen and ("\\syswow64\\" in filenamelower or "\\system32\\" in filenamelower):
                self.nextopen = filename
                if self.pid:
                    self.mark_call()
        elif call["api"].startswith("CopyFile") and self.saw_disable and not self.nextopen:
            filename = self.get_argument(call, "NewFileName")
            filenamelower = filename.lower()
            if "\\syswow64\\" in filenamelower or "\\system32\\" in filenamelower:
                self.nextopen = filename
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.saw_disable and self.nextopen:
            self.data.append({"Likely to allow modification of": self.nextopen})
        return self.saw_disable
