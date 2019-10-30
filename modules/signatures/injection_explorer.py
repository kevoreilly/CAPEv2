# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class InjectionExplorer(Signature):
    name = "injection_explorer"
    description = "Injected into Explorer using shared memory and window message technique"
    severity = 3
    categories = ["injection"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.parent = (str(), int())
        self.injected = (str(), int())
        self.sharedsections = ["\\basenamedobjects\\shimsharedmemory",
                                "\\basenamedobjects\\windows_shell_global_counters",
                                "\\basenamedobjects\\msctf.shared.sfm.mih",
                                "\\basenamedobjects\\msctf.shared.sfm.amf",
                                "\\basenamedobjects\\urlzonessm_administrator",
                                "\\basenamedobjects\\urlzonessm_system"]

    filter_apinames = set(["NtOpenSection", "NtCreateSection", "NtOpenProcess", "ReadProcessMemory", "NtReadVirtualMemory", "NtWow64ReadVirtualMemory64", "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW", "SendNotifyMessageA", "SendNotifyMessageW", "SetWindowLongA", "SetWindowLongW", "SetWindowLongPtrA", "SetWindowLongPtrW"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            self.lastprocess = process

        if call["api"] == "NtOpenSection" or call["api"] == "NtCreateSection":
            name = self.get_argument(call, "ObjectAttributes")
            if name.lower() in self.sharedsections:
                self.sequence = 1
        elif self.sequence == 1 and call["api"] == "NtOpenProcess":
            self.sequence = 2
            self.parent = (process["process_name"], process["process_id"])
            pid = str(self.get_argument(call, "ProcessIdentifier"))
            self.injected = (self.get_name_from_pid(pid), pid)
        elif self.sequence == 2 and (call["api"] == "ReadProcessMemory" or call["api"] == "NtReadVirtualMemory" or call["api"] == "NtWow64ReadVirtualMemory64"):
            self.sequence = 3
        elif self.sequence == 3 and call["api"].startswith("FindWindow"):
            classname = self.get_argument(call, "ClassName")
            if classname.lower() == "shell_traywnd":
                self.sequence = 4
        elif self.sequence == 4 and call["api"].startswith("SetWindowLong"):
            self.sequence = 5
        elif self.sequence == 5 and call["api"].startswith("SendNotifyMessage"):
            desc = "{0}({1}) -> {2}({3})".format(self.parent[0], self.parent[1],
                                                 self.injected[0], self.injected[1])
            self.data.append({"Injection": desc})
            return True
