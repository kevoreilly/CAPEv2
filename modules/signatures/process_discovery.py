# Copyright (C) 2020 Kevin Ross
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


class EmumeratesRunningProcesses(Signature):
    name = "enumerates_running_processes"
    description = "Enumerates running processes"
    severity = 2
    categories = ["discovery"]
    authors = ["Kevin Ross"]
    minimum = "0.5"
    evented = True
    ttps = ["T1057"]  # MITRE v6,7,8
    mbcs = ["OB0007"]

    filter_apinames = set(["Process32NextA", "Process32NextW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.enumeratedpids = []

    def on_call(self, call, process):
        procname = self.get_argument(call, "ProcessName")
        procpid = self.get_argument(call, "ProcessId")
        if procpid and procname:
            if procpid not in self.enumeratedpids and procpid != "0":
                self.enumeratedpids.append(procpid)
                self.data.append({"process": "%s with pid %s" % (procname, procpid)})
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if len(self.enumeratedpids) > 5:
            return True


class CreateToolhelp32SnapshotProcessModuleEnumeration(Signature):
    name = "createtoolhelp32snapshot_module_enumeration"
    description = "Enumerates the modules from a process (may be used to locate base addresses in process injection)"
    severity = 2
    categories = ["discovery"]
    authors = ["Kevin Ross"]
    minimum = "0.5"
    evented = True
    ttps = ["T1057"]  # MITRE v6,7,8
    mbcs = ["OB0007"]

    filter_apinames = set(["CreateToolhelp32Snapshot", "Module32NextA", "Module32NextW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.snapshotpids = []

    def on_call(self, call, process):
        if call["api"] == "CreateToolhelp32Snapshot":
            procpid = self.get_argument(call, "ProcessId")
            if procpid:
                if procpid not in self.snapshotpids and procpid != "0":
                    self.snapshotpids.append(procpid)
                    if self.pid:
                        self.mark_call()

        if call["api"].startswith("Module32Next"):
            procpid = self.get_argument(call, "ProcessId")
            modulename = self.get_argument(call, "ModuleName")
            if procpid in self.snapshotpids:
                self.ret = True
                self.data.append({"module": "pid %s module %s" % (procpid, modulename)})
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        return self.ret


class CmdlineProcessDiscovery(Signature):
    name = "cmdline_process_discovery"
    description = "Uses Windows utilities to enumerate running processes"
    severity = 2
    categories = ["discovery"]
    authors = ["Kevin Ross"]
    minimum = "0.5"
    evented = True
    ttps = ["T1057"]  # MITRE v6,7,8
    mbcs = ["OB0007"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "tasklist" in lower or ("powershell" in lower and "get-process" in lower):
                ret = True
                self.data.append({"command": cmdline})

        return ret
