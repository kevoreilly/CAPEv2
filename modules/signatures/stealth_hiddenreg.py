# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class StealthHiddenReg(Signature):
    name = "stealth_hiddenreg"
    description = "Attempts to modify Explorer settings to prevent hidden files from being displayed"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1054", "T1158"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.006", "T1564", "T1564.001"]  # MITRE v7,8
    mbcs = ["OB0006", "F0005", "F0006", "E1112", "E1478"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\Hidden$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\ShowSuperHidden$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\SuperHidden$",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True
        return False
