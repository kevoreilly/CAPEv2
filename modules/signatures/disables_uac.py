# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesUAC(Signature):
    name = "disables_uac"
    description = "Attempts to disable UAC"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1088"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v7,8
    ttps += ["T1548", "T1548.002"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        if self.check_write_key(
            pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\EnableLUA$",
            regex=True,
        ):
            return True
        return False
