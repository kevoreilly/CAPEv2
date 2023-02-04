# Copyright (C) 2022 ditekshen
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


class PersistsDotNetDevUtility(Signature):
    name = "persists_dev_util"
    description = "Attempts to bypass application whitelisting by copying and persisting .NET utility"
    severity = 3
    categories = ["masquerading", "evasion", "execution", "dotnet"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1118"]  # MITRE v6
    ttps += ["T1127", "T1218"]  # MITRE v6,7,8
    ttps += ["T1218.004"]  # MITRE v7,8

    filter_apinames = set(["CopyFileA", "CopyFileW", "CopyFileExW", "RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.devtools = [
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegAsm\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\MSBuild\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegSvcs\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\InstallUtil\.exe", re.IGNORECASE),
        ]
        self.sname = str()
        self.dname = str()

    def on_call(self, call, process):
        if call["api"].startswith("CopyFile"):
            self.sname = self.get_argument(call, "ExistingFileName")
            if self.sname:
                for tool in self.devtools:
                    if re.search(tool, self.sname.lower()):
                        self.dname = self.get_argument(call, "NewFileName")

        if call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW":
            buff = self.get_argument(call, "Buffer")
            if buff and buff.lower() and self.dname.lower() and self.dname.lower() in buff.lower():
                self.data.append({"copy": self.sname.lower() + " > " + self.dname.lower()})
                fname = self.get_argument(call, "FullName")
                if fname:
                    self.data.append({"regkey": fname})
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if len(self.data) > 0:
            return True

        return False


class SpwansDotNetDevUtiliy(Signature):
    name = "spawns_dev_util"
    description = "Attempts to bypass application whitelisting"
    severity = 3
    categories = ["masquerading", "evasion", "execution", "dotnet"]
    authors = ["ditekshen", "Zane C. Bowers-Hadley"]
    minimum = "1.3"
    evented = True
    ttps = ["T1118"]  # MITRE v6
    ttps += ["T1127", "T1218"]  # MITRE v6,7,8
    ttps += ["T1218.004"]  # MITRE v7,8

    filter_apinames = set(
        ["CreateProcessInternalA", "CreateProcessInternalW", "CopyFileA", "CopyFileW", "CopyFileExW", "NtCreateUserProcess"]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.devtools = [
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegAsm\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\MSBuild\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegSvcs\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\InstallUtil\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\mscorsvw\.exe", re.IGNORECASE),
            re.compile("[A-Z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\CasPol\.exe", re.IGNORECASE),
            re.compile(
                "[A-Z]:\\\\\\\\Windows\\\\\\\\Microsoft\.NET\\\\\\\\Framework\\\\\\\\v.*\\\\\\\\MSBuild\.exe", re.IGNORECASE
            ),
        ]
        self.sname = str()
        self.dname = str()
        self.executecopy = False

    def on_call(self, call, process):
        if call["api"].startswith("CopyFile"):
            self.sname = self.get_argument(call, "ExistingFileName")
            if self.sname:
                for tool in self.devtools:
                    if re.search(tool, self.sname.lower()):
                        self.dname = self.get_argument(call, "NewFileName")

        if (
            call["api"] == "CreateProcessInternalA"
            or call["api"] == "CreateProcessInternalW"
            or call["api"] == "NtCreateUserProcess"
        ):
            cmdline = self.get_argument(call, "CommandLine").lower()
            appname = self.get_argument(call, "ApplicationName")
            if cmdline:
                creation_flags = self.get_argument(call, "CreationFlags")
                if creation_flags is None:
                    return
                flags = int(creation_flags, 16)
                # CREATE_SUSPENDED or CREATE_SUSPENDED|CREATE_NO_WINDOW
                if flags & 0x4 or flags & 0x08000004:
                    for tool in self.devtools:
                        if "{path}" in cmdline:
                            appname = self.get_argument(call, "ApplicationName")
                            if appname:
                                if re.search(tool, appname):
                                    procname = process["process_name"]
                                    self.data.append({"process": procname + " > " + appname})
                                    if self.pid:
                                        self.mark_call()
                        elif self.dname and self.dname.lower() in cmdline:
                            self.executecopy = True
                            procname = process["process_name"]
                            self.data.append({"copy": self.sname.lower() + " > " + self.dname.lower()})
                            self.data.append({"process": procname + " > " + self.dname.lower()})
                            if self.pid:
                                self.mark_call()
                        elif re.search(tool, cmdline):
                            procname = process["process_name"]
                            spawnapp = self.get_argument(call, "ApplicationName")
                            if not spawnapp:
                                spawnapp = cmdline
                            self.data.append({"process": procname + " > " + spawnapp})
                            if self.pid:
                                self.mark_call()
            # Handle cases were CommandLine is null
            elif appname:
                flags = int(self.get_argument(call, "CreationFlags"), 16)
                # CREATE_SUSPENDED or CREATE_SUSPENDED|CREATE_NO_WINDOW
                if flags & 0x4 or flags & 0x08000004:
                    for tool in self.devtools:
                        if re.search(tool, appname):
                            procname = process["process_name"]
                            self.data.append({"process": procname + " > " + appname})
                            if self.pid:
                                self.mark_call()

    def on_complete(self):
        if len(self.data) > 0:
            if self.executecopy:
                self.description = "{0} {1}".format(
                    self.description, "by copying and executing .NET utility in a suspended state, potentially for injection"
                )
            else:
                self.description = "{0} {1}".format(
                    self.description, "by executing .NET utility in a suspended state, potentially for injection"
                )
            return True

        return False
