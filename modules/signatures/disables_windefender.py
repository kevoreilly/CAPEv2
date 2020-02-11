# Copyright (C) 2016 Brad Spengler, 2019 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesWindowsDefender(Signature):
    name = "disables_windows_defender"
    description = "Attempts to disable Windows Defender"
    severity = 3
    categories = ["antiav"]
    authors = ["Brad Spengler", "Kevin Ross"]
    minimum = "1.2"
    ttp = ["T1089"]

    def run(self):
        ret = False

        keys = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Windows\\ Defender\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ Defender\\\\.*",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\WinDefend\\\\.*",
        ]

        cmds = [
            "disablebehaviormonitoring",
            "disableblockatfirstseen",
            "disableintrusionpreventionsystem",
            "disableioavprotection",
            "disableprivacymode",
            "disablerealtimemonitoring",
            "disablescriptscanning",
            "lowthreatdefaultaction",
            "moderatethreatdefaultaction",
            "severethreatdefaultaction",
        ]

        for check in keys:
            match = self.check_write_key(pattern=check, regex=True)
            if match:
                self.data.append({"regkey" : match})
                ret = True

        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for cmd in cmds:
                if cmd in lower or ("sc" in lower and ("stop" in lower or "delete" in lower or "disabled" in lower) and "windefend" in lower):
                    self.data.append({"cmdline" : cmdline})
                    ret = True
                    break

        return ret

class WindowsDefenderPowerShell(Signature):
    name = "windows_defender_powershell"
    description = "Attempts to modify Windows Defender using PowerShell"
    severity = 3
    categories = ["antiav"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttp = ["T1089"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "set-mppreference" in lower:
                self.data.append({"cmdline" : cmdline})
                ret = True
            if "add-mppreference" in lower and "exclusionpath" in lower:
                self.data.append({"cmdline" : cmdline})
                ret = True

        return ret
