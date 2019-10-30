# Copyright (C) 2016 Kevin Ross
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
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.bcdedit = False
        self.systemrepair = False
        self.ignorefailures = False
        self.testsigning = False

    filter_apinames = set(["CreateProcessInternalW","ShellExecuteExW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
        else:
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            cmdline = filepath + " " + params

        if "bcdedit" in cmdline:
            self.bcdedit = True

        if "bcdedit" in cmdline and "set" in cmdline and "recoveryenabled no" in cmdline or "recoveryenabled off" in cmdline:
            self.systemrepair = True

        if "bcdedit" in cmdline and "set" in cmdline and "ignoreallfailures" in cmdline:
            self.ignorefailures = True

        if "bcdedit" in cmdline and "set" in cmdline and "testsigning on" in cmdline:
            self.testsigning = True

    def on_complete(self):
        if self.bcdedit:
            self.weight += 1

        if self.systemrepair:
            self.data.append({"disables_system_recovery" : "Modifies the boot configuration to disable startup recovery"})
            self.severity = 3
            self.weight += 1


        if self.ignorefailures:
            self.data.append({"ignorefailures" : "Modifies the boot configuration to disable Windows error recovery"})
            self.weight += 1

        if self.testsigning:
            self.data.append({"driver_testsigning" : "Modifies the boot configuration to cause patchguard to ignore unsigned drivers"})
            self.weight += 1

        if self.weight:
            return True
        return False
