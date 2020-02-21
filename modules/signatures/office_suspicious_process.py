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
    description = "Office document spawned a series of suspicious children processes"
    severity = 3
    categories = ["evasion", "execution", "dropper", "office", "lolbin"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["1127", "T1500"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["winword", "excel.exe", "powerpnt.exe"]
        self.suspiciousprocs = ["msbuild.exe", "cmd.exe", "wscript.exe", "cscript.exe", "powershell.exe", "csc.exe"]
        self.mastertrigger = False
        self.secondarytrigger = False

    filter_apinames = set(["CreateProcessInternalW", "NtCreateUserProcess"])

    def on_call(self, call, process):
        processname = process["process_name"].lower()
        if processname in self.officeprocs:
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                for proc in self.suspiciousprocs:
                    if proc in cmdline:
                        self.mastertrigger = True
        
        if processname in self.suspiciousprocs:
             cmdline = self.get_argument(call, "CommandLine")
             if cmdline:
                 for proc in self.suspiciousprocs:
                    if proc in cmdline:
                        self.secondarytrigger = True
    
    def on_complete(self):
        if self.results["info"]["package"] in ["doc", "xls", "ppt"]:
            if self.mastertrigger and self.secondarytrigger:
                return True
            
        return False
