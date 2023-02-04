# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class PreventsSafeboot(Signature):
    name = "prevents_safeboot"
    description = "Attempts to block SafeBoot use by removing registry keys"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1112", "T1490"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        if self.check_delete_key(
            pattern=".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\SafeBoot\\\\.*", regex=True
        ):
            return True
        return False
