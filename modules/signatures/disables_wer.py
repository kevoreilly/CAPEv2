# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesWER(Signature):
    name = "disables_wer"
    description = "Attempts to disable Windows Error Reporting"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1054"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v7,8
    ttps += ["T1562", "T1562.006"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112", "F0004", "F0006"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        if self.check_write_key(
            pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\Windows\\ Error\\ Reporting\\\\Disabled$",
            regex=True,
        ):
            return True

        return False
