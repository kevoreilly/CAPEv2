# Copyright (C) 2015 KillerInstinct
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

class Vawtrak_APIs(Signature):
    name = "vawtrak_behavior"
    description = "Exhibits behavior characteristics of Vawtrak / Neverquest malware."
    severity = 3
    weight = 3
    categories = ["banking", "trojan"]
    families = ["vawtrak", "neverquest"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
                           "NtOpenProcess", "NtCreateEvent", "NtOpenEvent", "RegSetValueExA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.vawtrakauto = False
        self.cevents = dict()
        self.oevents = dict()
        self.lastcall = str()
        self.nextlastcall = str()
        self.stepctr = 0
        self.pidwalk = 0

    def on_call(self, call, process):
        regsvr = "c:\\windows\\system32\\regsvr32.exe"
        curproc = process["process_name"]

        if call["api"] == "RegSetValueExA":
            # Autorun registry / filesystem behavior
            buf = self.get_argument(call, "FullName").lower()
            if "\\software\\microsoft\\windows\\currentversion\\run\\" in buf:
                val = self.get_argument(call, "ValueName").lower()
                buff = self.get_argument(call, "Buffer").lower()
                if "regsvr32.exe" in buff:
                    if "\\programdata\\" + val + "\\" in buff:
                        self.vawtrakauto = True

        if call["api"] == "CreateToolhelp32Snapshot":
            if process["module_path"].lower() == regsvr:
                if self.pidwalk == 0:
                    self.pidwalk += 1

        elif call["api"] == "Process32FirstW":
            if process["module_path"].lower() == regsvr:
                if self.pidwalk > 0:
                    self.pidwalk += 1

        elif call["api"] == "Process32NextW":
            if self.pidwalk > 1:
                self.pidwalk += 1

        elif call["api"] == "NtCreateEvent":
            # Increase process injection event counter
            if curproc == "regsvr32.exe":
                if (self.nextlastcall == "Process32FirstW" or self.nextlastcall == "Process32NextW") and self.lastcall == "NtOpenProcess":
                    self.stepctr += 1
            # Add event to process event monitor
            modpath = process["module_path"].lower()
            if modpath not in self.cevents:
                self.cevents[modpath] = set()
            self.cevents[modpath].add(self.get_argument(call, "EventName"))

        elif call["api"] == "NtOpenEvent":
            # Add event to process event monitor
            modpath = process["module_path"].lower()
            if modpath not in self.oevents:
                self.oevents[modpath] = set()
            self.oevents[modpath].add(self.get_argument(call, "EventName"))

        self.nextlastcall = self.lastcall
        self.lastcall = call["api"]


    def on_complete(self):
        malscore = 0
        # Check for autorun registry/filesystem behavior
        if self.vawtrakauto:
            malscore += 4

        # Check for process injection event behavior
        if self.stepctr > 2:
            malscore += 2

        # Check for regsvr32.exe process enumeration
        if self.pidwalk > 20:
            malscore += 2

        dllpath = "c:\\windows\\system32\\regsvr32.exe"
        explorerpath = "c:\\windows\\explorer.exe"
        # Check for process injection into explorer trigger
        if dllpath in self.cevents and explorerpath in self.cevents:
            for event in self.cevents[dllpath]:
                if event in self.cevents[explorerpath]:
                    malscore += 6

        # Check for autorun test event trigger
        if dllpath in self.oevents and explorerpath in self.cevents:
            for event in self.oevents[dllpath]:
                if event in self.cevents[explorerpath]:
                    malscore += 6

        if malscore >= 10:
            return True
        else:
            return False
