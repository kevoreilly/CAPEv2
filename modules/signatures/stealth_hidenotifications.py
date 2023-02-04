# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class StealthHideNotifications(Signature):
    name = "stealth_hide_notifications"
    description = "Attempts to modify user notification settings"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1054"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.006"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112", "E1478", "F0006"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\HideSCAHealth$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Advanced\\\\TaskbarNoNotification$",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True
        return False
