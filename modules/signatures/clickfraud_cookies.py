# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ClickfraudCookies(Signature):
    name = "clickfraud_cookies"
    description = "Overrides system cookie policy, indicative of click fraud"
    severity = 3
    categories = ["clickfraud"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["InternetSetOptionA"])

    def on_call(self, call, process):
        handle = int(self.get_argument(call, "InternetHandle"), 16)
        option = int(self.get_argument(call, "Option"), 16)
        # INTERNET_OPTION_SUPPRESS_BEHAVIOR
        if option == 81:
            val = 0
            try:
                val = int(self.get_argument(call, "Buffer"), 16)
            except:
                pass
            # INTERNET_SUPPRESS_COOKIE_POLICY
            if not handle and val == 1:
                return True
