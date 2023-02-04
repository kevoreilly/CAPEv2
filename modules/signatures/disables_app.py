# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesAppLaunch(Signature):
    name = "disables_app_launch"
    description = "Modifies system policies to prevent the launching of specific applications or executables"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.001"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112", "E1478", "F0004", "F0004.005"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        if self.check_write_key(
            pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\DisallowRun$",
            regex=True,
        ):
            return True

        return False
