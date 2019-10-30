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

class DEPBypass(Signature):
    name = "dep_bypass"
    description = "DEP was bypassed by marking part of the heap executable"
    severity = 3
    categories = ["exploit"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ignore_it = True
        self.procs = set()
        if self.results["target"]["category"] != "file" or self.results["info"]["package"] not in ["exe", "rar", "zip", "dll", "regsvr"]:
            self.ignore_it = False

    filter_apinames = set(["NtProtectVirtualMemory", "VirtualProtectEx"])

    def on_call(self, call, process):
        if self.ignore_it:
            return False

        # CoW'd memory will still be MEM_IMAGE/MEM_MAPPED as appropriate
        # MEM_PRIVATE = 0x20000
        memtype = self.get_argument(call, "MemType")
        if memtype == None:
            return False

        if memtype != 0x20000:
            return

        # PAGE_READWRITE = 4
        # PAGE_EXECUTE_READWRITE = 0x40
        oldprotect = 0
        newprotect = 0
        if call["api"] == "NtProtectVirtualMemory":
            oldprotect = int(self.get_argument(call, "OldAccessProtection"), 16)
            newprotect = int(self.get_argument(call, "NewAccessProtection"), 16)
        else:
            oldprotect = int(self.get_argument(call, "OldProtection"), 16)
            newprotect = int(self.get_argument(call, "Protection"), 16)

        if oldprotect == 4 and newprotect == 0x40:
            self.procs.add(process["process_name"] + ":" + str(process["process_id"]))

    def on_complete(self):
        for proc in self.procs:
            self.data.append({"process" : proc})

        if self.procs:
            return True
        return False
