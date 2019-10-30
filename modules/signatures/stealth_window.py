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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Hidden_Window(Signature):
    name = "stealth_window"
    description = "A process created a hidden window"
    severity = 2
    categories = ["stealth"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.hidden = list()

    filter_apinames = set(["ShellExecuteExW", "CreateProcessInternalW"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            clbuf = self.get_argument(call, "CommandLine").lower()
            cfbuf = int(self.get_argument(call, "CreationFlags"), 16)
            # Handle Powershell CommandLine Arguments
            if "powershell" in clbuf and (re.search("-win[ ]+hidden", clbuf) or
                                          re.search("-windowstyle[ ]+hidden", clbuf)):
                proc = process["process_name"]
                spawn = self.get_argument(call, "ApplicationName")
                if not spawn:
                    spawn = self.get_argument(call, "CommandLine")
                self.hidden.append((proc, spawn))
                self.data.append({"Process": proc + " -> " + spawn})
            # Handle CREATE_NO_WINDOW flag, ignored for CREATE_NEW_CONSOLE and DETACHED_PROCESS
            elif cfbuf & 0x08000000 and  not (cfbuf & 0x10 or cfbuf & 0x8):
                proc = process["process_name"]
                spawn = self.get_argument(call, "ApplicationName")
                if not spawn:
                    spawn = self.get_argument(call, "CommandLine")
                self.hidden.append((proc, spawn))
                self.data.append({"Process": proc + " -> " + spawn})

        elif call["api"] == "ShellExecuteExW":
            buf = int(self.get_argument(call, "Show"), 10)
            # Handle SW_HIDE flag
            if buf == 0:
                proc = process["process_name"]
                spawn = self.get_argument(call, "FilePath")
                self.hidden.append((proc, spawn))
                self.data.append({"Process": proc + " -> " + spawn})

    def on_complete(self):
        ret = False
        if len(self.hidden) > 0:
            ret = True

        return ret
