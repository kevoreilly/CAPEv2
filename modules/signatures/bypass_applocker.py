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

class SquiblydooBypass(Signature):
    name = "squiblydoo_bypass"
    description = "Attempts to bypass application controls using the squiblydoo technique"
    severity = 3
    confidence = 90
    categories = ["bypass", "command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1117"]
    
    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "regsvr32" in lower and ("/s" in lower or "-s" in lower) and ("/u" in lower or "-u" in lower) and ("scrobj" in lower or "vbscript" in lower or "jscript" in lower):
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class RegSrv32SquiblydooDLLLoad(Signature):
    name = "regsvr32_squiblydoo_dll_load"
    description = "RegSvr32 loaded a DLL related the to squiblydoo application control bypass technique"
    severity = 3
    categories = ["bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    ttp = ["T1086", "T1117"]

    filter_apinames = set(["LdrLoadDll"])

    def on_call(self, call, process):
        pname = process["process_name"]
        if pname.lower() == "regsvr32.exe":
            filename = self.get_argument(call, "FileName")
            if filename.lower() in ["scrobj.dll", "jscript.dll", "vbscript.dll"]:
                return True

class SquiblytwoBypass(Signature):
    name = "squiblytwo_bypass"
    description = "Attempts to bypass application controls using the squiblytwo technique"
    severity = 3
    confidence = 90
    categories = ["bypass", "command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1117"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "wmic" in lower and "process" in lower and "list" in lower and "format:" in lower:
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class OdbcconfBypass(Signature):
    name = "odbcconf_bypass"
    description = "Attempts to bypass application controls using odbcconf"
    severity = 3
    confidence = 70
    categories = ["bypass", "command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1086", "T1117"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "odbcconf" in lower and "regsvr" in lower:
                ret = True
                self.data.append({"command" : cmdline})

        return ret
