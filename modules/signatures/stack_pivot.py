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


class StackPivot(Signature):
    name = "stack_pivot"
    description = "Stack pivoting was detected when using a critical API"
    severity = 3
    confidence = 100
    categories = ["exploit"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True
    ttps = ["T1203"]  # MITRE v6,7,8
    mbcs = ["OB0009", "E1203"]

    filter_apinames = set(
        [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "VirtualProtectEx",
            "NtWriteVirtualMemory",
            "NtWow64WriteVirtualMemory64",
            "WriteProcessMemory",
            "NtMapViewOfSection",
            "URLDownloadToFileW",
        ]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.procs = set()
        self.processes = [
            "acrobat.exe",
            "chrome.exe",
            "FLTLDR.EXE",
            "firefox.exe",
            "HimTrayIcon.exe",
            "hwp.exe",
            "iexplore.exe",
            "outlook.exe",
        ]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.processes:
            pivot = self.get_argument(call, "StackPivoted")
            if pivot is None:
                return
            if pivot == "yes":
                self.procs.add(process["process_name"] + ":" + str(process["process_id"]))
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        for proc in self.procs:
            self.data.append({"process": proc})

        if self.data:
            return True
        else:
            return False


class StackPivotFileCreated(Signature):
    name = "stack_pivot_file_created"
    description = "A file was created using stack pivoting"
    severity = 3
    confidence = 100
    categories = ["exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1203"]  # MITRE v6,7,8
    mbcs = ["OB0009", "E1203"]
    mbcs += ["OC0001", "C0016"]  # micro-behaviour

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.processes = [
            "acrobat.exe",
            "acrord32.exe",
            "chrome.exe",
            "excel.exe",
            "FLTLDR.EXE",
            "firefox.exe",
            "HimTrayIcon.exe",
            "hwp.exe",
            "iexplore.exe",
            "outlook.exe",
            "powerpnt.exe",
            "winword.exe",
        ]

    def on_call(self, call, process):
        pname = process["process_name"]
        if pname.lower() in self.processes:
            pivot = self.get_argument(call, "StackPivoted")
            filename = self.get_argument(call, "FileName")
            if pivot == "yes":
                self.data.append({pname: filename})
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.data:
            return True
        else:
            return False


class StackPivotProcessCreate(Signature):
    name = "stack_pivot_process_create"
    description = "A process was created using stack pivoting"
    severity = 3
    confidence = 100
    categories = ["exploit"]
    authors = ["Kevin Ross", "Zane C. Bowers-Hadley"]
    minimum = "1.3"
    evented = True
    ttps = ["T1203"]  # MITRE v6,7,8
    mbcs = ["OB0009", "E1203"]
    mbcs += ["OC0003", "C0017"]  # micro-behaviour

    filter_apinames = set(["CreateProcessInternalW", "NtCreateUserProcess"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.processes = [
            "acrobat.exe",
            "acrord32.exe",
            "chrome.exe",
            "excel.exe",
            "FLTLDR.EXE",
            "firefox.exe",
            "HimTrayIcon.exe",
            "hwp.exe",
            "iexplore.exe",
            "outlook.exe",
            "powerpnt.exe",
            "winword.exe",
        ]

    def on_call(self, call, process):
        pname = process["process_name"]
        if pname.lower() in self.processes:
            pivot = self.get_argument(call, "StackPivoted")
            cmdline = self.get_argument(call, "CommandLine")
            if pivot == "yes":
                self.data.append({pname.replace(".", "_"): cmdline})
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.data:
            return True
        else:
            return False
