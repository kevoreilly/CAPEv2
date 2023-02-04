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


class AntiVMDirectoryObjects(Signature):
    name = "antivm_directory_objects"
    description = "The sample enumerated directory objects, possibly probing for Virtual Machine objects."
    severity = 2
    confidence = 80
    categories = ["anti-vm"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttps = ["T1083"]  # MITRE v6,7,8
    ttps += ["U1332"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.001", "OB0007", "E1083"]
    mbcs += ["OC0001"]  # micro-behaviour

    filter_apinames = set(["NtOpenDirectoryObject", "NtQueryDirectoryObject"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.check_dirs = set()
        self.directories = set()
        self.dirbuf = tuple()
        self.lastapi = str()

    def on_call(self, call, process):
        if call["api"] == "NtOpenDirectoryObject":
            dirhandle = self.get_argument(call, "DirectoryHandle")
            objectattr = self.get_argument(call, "ObjectAttributes")
            self.dirbuf = (dirhandle, objectattr)
        elif call["api"] == "NtQueryDirectoryObject":
            dirhandle = self.get_argument(call, "DirectoryHandle")
            if self.lastapi == "NtOpenDirectoryObject":
                if self.dirbuf and dirhandle == self.dirbuf[0]:
                    # Basic check for enumeration
                    if call["repeated"] > 40:
                        self.check_dirs.add(self.dirbuf[1])
            if self.lastapi == "NtQueryDirectoryObject":
                if self.dirbuf and dirhandle == self.dirbuf[0]:
                    # Check for NO_MORE_ENTRIES return
                    if call["return"] == "0x8000001a":
                        if self.dirbuf[1] in self.check_dirs:
                            self.directories.add(self.dirbuf[1])
                            if self.pid:
                                self.mark_call()

        self.lastapi = call["api"]

    def on_complete(self):
        if self.directories:
            for dirobj in self.directories:
                self.data.append({"Object": dirobj})
                self.weight += 1
            return True

        return False
