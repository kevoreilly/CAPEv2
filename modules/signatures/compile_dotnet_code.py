# Copyright (C) 2019 ditekshen
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

class CompilesDotNetCode(Signature):
    name = "dotnet_code_compile"
    description = "Compiles .NET code into an executable and executes it"
    severity = 3
    categories = ["evasion", "execution", "dropper", "dotnet", "exploit", "office"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1500"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
        self.csccmd = False
        self.cvtrescmd = False
        self.writemz = False

    filter_apinames = set(["CreateProcessInternalA", "CreateProcessInternalW", "NtWriteFile"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalA" or call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                if "csc.exe" in cmdline or "vbc.exe" in cmdline:
                    self.csccmd = True
                    self.data.append({"command": cmdline})

        processname = process["process_name"].lower()
        if processname == "csc.exe" or processname == "vbc.exe":
            if call["api"] == "CreateProcessInternalA" or call["api"] == "CreateProcessInternalW":
                cmdline = self.get_argument(call, "CommandLine")
                if cmdline:
                    if "cvtres.exe" in cmdline:
                        self.cvtrescmd = True
                        self.data.append({"command": cmdline })
            
            if call["api"] == "NtWriteFile":
                buff = self.get_argument(call, "Buffer")
                if buff:
                    if buff.startswith("MZ"):
                        self.writemz = True
    
    def on_complete(self):
        match = False
        expscore = 0
        indicators = [
            ".*\.pdb",
            ".*\.(cs|CS)",
            ".*\.(vb|VB)",
            ".*\.cmdline",
            ".*\.(dll|DLL)",
            ".*\.(exe|EXE)",
            ".*\.(tmp|TMP)",
        ]

        if (self.csccmd or self.cvtrescmd) and self.writemz:
            for indicator in indicators:
                if self.results.get("dropped", []):
                    for dropped in self.results["dropped"]:
                        filename = dropped["name"]
                        filetype = dropped["type"]
                        if re.match(indicator, filename, re.IGNORECASE):
                            match = True
                            if filename.endswith(".pdb") or "Logo." in filename:
                                expscore += 1
                            for filepath in dropped["guest_paths"]:
                                if filename.endswith(".tmp") or filename.endswith(".TMP"):
                                    if "COFF" in filetype or "MSVC" in filetype:
                                        self.data.append({"file": filepath})
                                else:
                                    self.data.append({"file": filepath})

            if match and self.results["info"]["package"] in ["doc", "xls", "ppt"] and expscore >= 2:
                self.description += " potentially via exploiting CVE-2017-8759"
                return True
            elif match:
                return True
            
        return False

