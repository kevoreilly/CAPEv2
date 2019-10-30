# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAVSRP(Signature):
    name = "antiav_srp"
    description = "Modifies Software Restriction Policies likely to cripple AV"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1089"]

    def run(self):
        match_key = self.check_write_key(".*\\\\Policies\\\\Microsoft\\\\Windows\\\\Safer\\\\\CodeIdentifiers\\\\0\\\\Paths\\\\.*", regex=True, all=True)
        if match_key:
            for match in match_key:
                self.data.append({"key" : match})
            return True
        return False
