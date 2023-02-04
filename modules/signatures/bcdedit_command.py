# Copyright (C) 2022 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class BCDEditCommand(Signature):
    name = "bcdedit_command"
    description = "Modifies boot configuration settings"
    severity = 3
    confidence = 20
    weight = 0
    categories = ["generic"]
    authors = ["Kevin Ross", "Zane C. Bowers-Hadley"]
    minimum = "1.2"
    evented = True
    ttps = ["T1059"]  # MITRE v6,7,8
    ttps += ["T1059.003"]  # MITRE v7,8
    mbcs = ["OB0006", "E1478", "OB0009", "E1059"]
    mbcs += ["OC0008", "C0033"]  # micro-behaviour

    filter_apinames = set(["CreateProcessInternalW", "ShellExecuteExW", "NtCreateUserProcess"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.bcdedit = False
        self.systemrepair = False
        self.ignorefailures = False
        self.testsigning = False

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
        elif call["api"] == "NtCreateUserProcess":
            cmdline = self.get_argument(call, "CommandLine").lower()
        else:
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            cmdline = filepath + " " + params

        if "bcdedit" in cmdline:
            if self.pid:
                self.mark_call()
            self.bcdedit = True

        if "bcdedit" in cmdline and "set" in cmdline and "recoveryenabled no" in cmdline or "recoveryenabled off" in cmdline:
            if self.pid:
                self.mark_call()
            self.systemrepair = True

        if "bcdedit" in cmdline and "set" in cmdline and "ignoreallfailures" in cmdline:
            if self.pid:
                self.mark_call()
            self.ignorefailures = True

        if "bcdedit" in cmdline and "set" in cmdline and "testsigning on" in cmdline:
            if self.pid:
                self.mark_call()
            self.testsigning = True

    def on_complete(self):
        if self.bcdedit:
            self.weight += 1

        if self.systemrepair:
            self.data.append({"disables_system_recovery": "Modifies the boot configuration to disable startup recovery"})
            self.severity = 3
            self.weight += 1
            self.ttps += ["T1490"]  # MITRE v6,7,8

        if self.ignorefailures:
            self.data.append({"ignorefailures": "Modifies the boot configuration to disable Windows error recovery"})
            self.weight += 1
            self.ttps += ["T1490"]  # MITRE v6,7,8

        if self.testsigning:
            self.data.append(
                {"driver_testsigning": "Modifies the boot configuration to cause patchguard to ignore unsigned drivers"}
            )
            self.weight += 1

        if self.weight:
            return True
        return False
