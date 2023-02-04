# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesWindowsUpdate(Signature):
    name = "disables_windowsupdate"
    description = "Attempts to disable Windows Auto Updates"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1112"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        if self.check_write_key(
            pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\\\WindowsUpdate\\\\(AU\\\\NoAutoUpdate|Auto\\ Update\\\\AUOptions)$",
            regex=True,
        ):
            return True
        return False
