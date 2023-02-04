# Copyright (C) 2020 ditekshen
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


class OfficeSuspiciousProcesses(Signature):
    name = "office_suspicious_processes"
    description = "Office document spawned a series of suspicious child processes"
    severity = 3
    categories = ["evasion", "execution", "dropper", "office"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1064", "T1500"]  # MITRE v6
    ttps += ["T1059", "T1127"]  # MITRE v6,7,8
    ttps += ["T1027.004"]  # MITRE v7,8
    mbcs = ["OB0009", "E1059"]

    filter_apinames = set(["CreateProcessInternalW", "NtCreateUserProcess"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["winword", "excel.exe", "powerpnt.exe"]
        self.suspiciousprocs = ["msbuild.exe", "cmd.exe", "wscript.exe", "cscript.exe", "powershell.exe", "csc.exe", "msdt.exe"]
        self.mastertrigger = False
        self.secondarytrigger = False

    def on_call(self, call, process):
        processname = process["process_name"].lower()
        if processname in self.officeprocs:
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                for proc in self.suspiciousprocs:
                    if proc in cmdline:
                        self.mastertrigger = True
                        if self.pid:
                            self.mark_call()

        if processname in self.suspiciousprocs:
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                for proc in self.suspiciousprocs:
                    if proc in cmdline:
                        self.secondarytrigger = True
                        if self.pid:
                            self.mark_call()

    def on_complete(self):
        if self.results["info"]["package"] in ["doc", "xls", "ppt"]:
            if self.mastertrigger and self.secondarytrigger:
                return True

        return False
