# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com)
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

class DebugsSelf(Signature):
    name = "debugs_self"
    description = "Debugs itself to thwart analysis"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
       createflags = int(self.get_argument(call, "CreationFlags"), 16)
       applicationname = self.get_argument(call, "ApplicationName").lower()
       pid = self.get_argument(call, "ProcessId")
       if createflags & 1:
           for proc in self.results["behavior"]["processes"]:
               if proc["process_id"] == pid and proc["module_path"].lower() == process["module_path"].lower():
                   # DEBUG_PROCESS on a copy of ourselves
                   return True
