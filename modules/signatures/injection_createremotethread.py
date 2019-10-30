# Copyright (C) 2012-2016 JoseMi "h0rm1" Holguin (@j0sm1), Optiv, Inc. (brad.spengler@optiv.com), KillerInstinct
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

class InjectionCRT(Signature):
    name = "injection_createremotethread"
    description = "Code injection with CreateRemoteThread in a remote process"
    severity = 3
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex", "Optiv", "KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_categories = set(["process","threading"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            self.process_handles = set()
            self.process_pids = set()
            self.handle_map = dict()
            self.lastprocess = process

        if call["api"] == "OpenProcess" and call["status"] == True:
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                handle = call["return"]
                pid = str(self.get_argument(call, "ProcessId"))
                self.process_handles.add(handle)
                self.process_pids.add(pid)
                self.handle_map[handle] = pid
        elif call["api"] == "NtOpenProcess" and call["status"] == True:
            if self.get_argument(call, "ProcessIdentifier") != process["process_id"]:
                handle = self.get_argument(call, "ProcessHandle")
                pid = str(self.get_argument(call, "ProcessIdentifier"))
                self.process_handles.add(handle)
                self.process_pids.add(pid)
                self.handle_map[handle] = pid
        elif (call["api"] == "NtMapViewOfSection") and self.sequence == 0:
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = 2
        elif (call["api"] == "VirtualAllocEx" or call["api"] == "NtAllocateVirtualMemory") and self.sequence == 0:
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = 1
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory") and self.sequence == 1:
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = 2
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64"  or call["api"] == "WriteProcessMemory") and self.sequence == 2:
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.process_handles:
                addr = int(self.get_argument(call, "BaseAddress"), 16)
                buf = self.get_argument(call, "Buffer")
                if addr >= 0x7c900000 and addr < 0x80000000 and buf.startswith("\\xe9"):
                    self.description = "Code injection via WriteProcessMemory-modified NTDLL code in a remote process"
                    procname = self.get_name_from_pid(self.handle_map[handle])
                    desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                                                         procname, self.handle_map[handle])
                    self.data.append({"Injection": desc})
                    return True
        elif (call["api"] == "CreateRemoteThread" or call["api"].startswith("NtCreateThread")) and self.sequence == 2:
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.process_handles:
                procname = self.get_name_from_pid(self.handle_map[handle])
                desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                                                     procname, self.handle_map[handle])
                self.data.append({"Injection": desc})
                return True
        elif call["api"].startswith("NtQueueApcThread") and self.sequence == 2:
            if str(self.get_argument(call, "ProcessId")) in self.process_pids:
                self.description = "Code injection with NtQueueApcThread in a remote process"
                desc = "{0}({1}) -> {2}({3})".format(self.lastprocess["process_name"], str(self.lastprocess["process_id"]),
                                                     process["process_name"], str(process["process_id"]))
                self.data.append({"Injection": desc})
                return True

