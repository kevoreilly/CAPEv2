# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAVServiceStop(Signature):
    name = "antiav_servicestop"
    description = "Attempts to stop active services"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1031", "T1089"]  # MITRE v6
    ttps += ["T1489"]  # MITRE v6,7,8
    ttps += ["T1543", "T1543.003", "T1562", "T1562.001"]  # MITRE v7,8
    mbcs = ["OB0006", "F0004", "F0011"]

    filter_apinames = set(["OpenServiceW", "OpenServiceA", "ControlService"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.handles = dict()
        self.lastprocess = 0
        self.stoppedservices = []

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if (call["api"] == "OpenServiceA" or call["api"] == "OpenServiceW") and call["status"]:
            handle = int(call["return"], 16)
            self.handles[handle] = self.get_argument(call, "ServiceName")
            if self.pid:
                self.mark_call()
        elif call["api"] == "ControlService":
            handle = int(self.get_argument(call, "ServiceHandle"), 16)
            code = int(self.get_argument(call, "ControlCode"), 10)
            if code == 1 and handle in self.handles and self.handles[handle] not in self.stoppedservices:
                self.stoppedservices.append(self.handles[handle])
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        ret = False
        if self.stoppedservices:
            ret = True
            for service in self.stoppedservices:
                self.data.append({"service": service})
        return ret
