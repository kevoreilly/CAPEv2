# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class AntiAVServiceStop(Signature):
    name = "antiav_servicestop"
    description = "Attempts to stop active services"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttp = ["T1031", "T1089"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.handles = dict()
        self.lastprocess = 0
        self.stoppedservices = []

    filter_apinames = set(["OpenServiceW", "OpenServiceA", "ControlService"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if (call["api"] == "OpenServiceA" or call["api"] == "OpenServiceW") and call["status"]:
            handle = int(call["return"], 16)
            self.handles[handle] = self.get_argument(call, "ServiceName")
        elif call["api"] == "ControlService":
            handle = int(self.get_argument(call, "ServiceHandle"), 16)
            code = int(self.get_argument(call, "ControlCode"), 10)
            if code == 1 and handle in self.handles and self.handles[handle] not in self.stoppedservices:
                self.stoppedservices.append(self.handles[handle])

    def on_complete(self):
        ret = False
        if self.stoppedservices:
            ret = True
            for service in self.stoppedservices:
                self.data.append({"servicename" : service })
        return ret
