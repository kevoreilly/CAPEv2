# Copyright (C) 2020 Kevin Ross
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


class ProcessCreationSuspiciousLocation(Signature):
    name = "process_creation_suspicious_location"
    description = "Created a process from a suspicious location"
    severity = 3
    confidence = 20
    categories = ["execution"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1106"]

    filter_apinames = set(["CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.ignore_proc_list = []
        self.suspicious_paths = [
            "\\AppData\\Roaming\\",
            "\\AppData\\Local\\Temp\\",
        ]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname not in self.ignore_proc_list:
            appname = self.get_argument(call, "ApplicationName")
            cmdline = self.get_argument(call, "CommandLine")
            for suspiciouspath in self.suspicious_paths:
                if suspiciouspath in appname:
                    self.ret = True
                    self.data.append({"file": appname})
                    self.data.append({"command": cmdline})
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        return self.ret
