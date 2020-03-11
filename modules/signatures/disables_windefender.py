# Copyright (C) 2016 Brad Spengler, 2019 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import re

class DisablesWindowsDefender(Signature):
    name = "disables_windows_defender"
    description = "Attempts to disable Windows Defender"
    severity = 3
    categories = ["antiav"]
    authors = ["Brad Spengler", "Kevin Ross", "ditekshen"]
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
            "disableantispyware",
            "disableantivirus",
            "disableonaccessprotection",
            "disablescanonrealtimeenable",
            "tamperprotection",
            "disableenhancednotification",
            "mpenablepus",
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

class RemovesWindowsDefenderContextMenu(Signature):
    name = "removes_windows_defender_contextmenu"
    description = "Attempts to remove Windows Defender from context menu"
    severity = 3
    categories = ["antiav"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1089"]

    def run(self):
        indicators = [
            "HKEY_CLASSES_ROOT\\\\\*\\\\shellex\\\\ContextMenuHandlers\\\\EPP$",
            "HKEY_CLASSES_ROOT\\\\Directory\\\\shellex\\\\ContextMenuHandlers\\\\EPP$",
            "HKEY_CLASSES_ROOT\\\\Drive\\\\shellex\\\\ContextMenuHandlers\\\\EPP$",
        ]
        pat = re.compile('.*\\\\shellex\\\\contextmenuhandlers\\\\epp')

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                return True

        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if re.search(pat, lower):
                self.data.append({"cmdline" : cmdline})
                return True

        return False

class DisablesWindowsDefenderLogging(Signature):
    name = "disables_windows_defender_logging"
    description = "Attempts to disable Windows Defender logging"
    severity = 3
    categories = ["antiav"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1089"]

    def run(self):
        indicators = [
            ".*\\\\System\\\\CurrentControlSet\\\\Control\\\\WMI\\\\Autologger\\\\Defender(Api|Audit)Logger",
        ]
        pat = re.compile('.*\\\\system\\\\currentcontrolset\\\\control\\\\wmi\\\\autologger\\\\defender(api|audit)logger')

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                return True

        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if re.search(pat, lower):
                self.data.append({"cmdline" : cmdline})
                return True

        return False
