# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class RemovesZoneIdADS(Signature):
    name = "removes_zoneid_ads"
    description = "Attempts to remove evidence of file being downloaded from the Internet"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.0"
    evented = True
    ttps = ["T1096"]  # MITRE v6
    ttps += ["T1070"]  # MITRE v6,7,8
    ttps += ["T1564", "T1564.004"]  # MITRE v7,8
    mbcs = ["OC0001", "C0047"]  # micro-behaviour

    filter_apinames = set(["DeleteFileA", "DeleteFileW"])

    def on_call(self, call, process):
        if call["api"].startswith("DeleteFile") and self.get_argument(call, "FileName").endswith(":Zone.Identifier"):
            self.data.append({"file": self.get_argument(call, "FileName")})
            if self.pid:
                self.mark_call()
            return True

        return None
