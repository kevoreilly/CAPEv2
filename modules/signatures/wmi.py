# Copyright (C) 2019 Kevin Ross
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

class WMICreateProcess(Signature):
    name = "wmi_create_process"
    description = "Windows Management Instrumentation (WMI) attempted to create a process"
    severity = 3
    confidence = 50
    categories = ["martians"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1047"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.whitelist = [
            "werfault.exe",
        ]

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        pname = process["process_name"]
        if "wmiprvse" in pname.lower()  or "scrcons" in pname.lower():           
            cmdline = self.get_argument(call, "CommandLine")
            whitelisted = False
            for whitelist in self.whitelist:
                if whitelist in cmdline.lower():
                    whitelisted = True
                    break
            if not whitelisted:
                self.ret = True
                self.data.append({"cmdline" : cmdline})

    def on_complete(self):
        return self.ret
    
class WMIScriptProcess(Signature):
    name = "wmi_script_process"
    description = "Windows Management Instrumentation (WMI) attempted to execute a command or scripting utility"
    severity = 3
    confidence = 100
    categories = ["martians"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1047"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.utilities = [
            "cmd ",
            "cmd.exe",
            "cscript",
            "jscript",
            "mshta",
            "powershell",
            "vbscript",
            "wscript",
        ]

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        pname = process["process_name"]
        if "wmiprvse" in pname.lower():
            cmdline = self.get_argument(call, "CommandLine")
            for utility in self.utilities:
                if utility in cmdline.lower():           
                    self.ret = True
                    self.data.append({"cmdline" : cmdline})
                    break

    def on_complete(self):
        return self.ret

class ScrconsWMIScriptConsumer(Signature):
    name = "scrcons_wmi_script_consumer"
    description = "Windows Management Instrumentation (WMI) script consumer process was launched indicating script execution or using an event consumer for persistence"
    severity = 3
    confidence = 50
    categories = ["wmi"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1047"]
	
    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "scrcons" in lower:
                self.data.append({"command" : cmdline})
                ret = True

        return ret
