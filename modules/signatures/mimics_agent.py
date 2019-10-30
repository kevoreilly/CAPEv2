# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MimicsAgent(Signature):
    name = "mimics_agent"
    description = "Mimics the system's user agent string for its own requests"
    severity = 2
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.useragent = None

    filter_apinames = set(["ObtainUserAgentString","InternetOpenA","InternetOpenW"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        if call["api"] == "ObtainUserAgentString":
            self.useragent = self.get_argument(call, "UserAgent")
        elif call["api"] == "InternetOpenA" or call["api"] == "InternetOpenW":
            agent = self.get_argument(call, "Agent")
            if self.useragent and self.useragent == agent:
                return True
