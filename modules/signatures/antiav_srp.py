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
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.001"]  # MITRE v7,8
    ttps += ["U0508"]  # Unprotect
    mbcs = ["OB0006", "E1478", "F0004", "F0004.005"]
    mbcs += ["OC0008", "C0036", "C0036.001"]  # micro-behaviours

    def run(self):
        match_key = self.check_write_key(
            ".*\\\\Policies\\\\Microsoft\\\\Windows\\\\Safer\\\\CodeIdentifiers\\\\0\\\\Paths\\\\.*", regex=True, all=True
        )
        if match_key:
            for match in match_key:
                self.data.append({"regkey": match})
            return True
        return False
