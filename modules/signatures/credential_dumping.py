# Copyright (C) 2018 Kevin Ross
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

class LsassCredentialDumping(Signature):
    name = "lsass_credential_dumping"
    description = "Requests access to read memory contents of lsass.exe potentially indicative of credential dumping"
    severity = 3
    categories = ["persistence", "lateral_movement", "credential_dumping"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["cyberwardog.blogspot.co.uk/2017/03/chronicles-of-threat-hunter-hunting-for_22.html", "cyberwardog.blogspot.co.uk/2017/04/chronicles-of-threat-hunter-hunting-for.html"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lsasspid = []
        self.lsasshandle = []
        self.readaccessprocs = []
        self.creddumpprocs = []
        self.ret = False

    filter_apinames = set(["NtOpenProcess", "Process32NextW", "ReadProcessMemory"])

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if self.get_argument(call, "ProcessName") == "lsass.exe":
                self.lsasspid.append(self.get_argument(call, "ProcessId"))

        if call["api"] == "NtOpenProcess":
            if self.get_argument(call, "ProcessIdentifier") in self.lsasspid and self.get_argument(call, "DesiredAccess") in ["0x00001010", "0x00001038"]:
                pname = process["process_name"].lower()
                if pname not in self.readaccessprocs:
                    self.data.append({"lsass read access": "The process %s requested read access to the lsass.exe process" % (pname)})
                    self.lsasshandle.append(self.get_argument(call, "ProcessHandle"))
                    self.readaccessprocs.append(pname)
                    self.ret = True
            
        if call["api"] == "ReadProcessMemory":
            if self.get_argument(call, "ProcessHandle") in self.lsasshandle:
                pname = process["process_name"].lower()
                if pname not in self.creddumpprocs:
                    self.description = "Locates and dumps memory from the lsass.exe process indicative of credential dumping"
                    self.data.append({"lsass credential dumping": "The process %s is reading memory from the lsass.exe process" % (pname)})
                    self.creddumpprocs.append(pname)
                    self.ret = True

    def on_complete(self):
        return self.ret
