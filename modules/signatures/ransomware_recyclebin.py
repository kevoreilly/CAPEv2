# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class RansomwareRecyclebin(Signature):
    name = "ransomware_recyclebin"
    description = "Empties the Recycle Bin, indicative of ransomware"
    severity = 3
    categories = ["ransomware"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1485"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1485"]
    mbcs += ["OC0001", "C0047"]  # micro-behaviour

    def run(self):
        if self.check_delete_file(pattern="C:\\\\RECYCLER\\\\.*", regex=True):
            return True
        return False
