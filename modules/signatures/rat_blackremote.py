# Copyright (C) 2020 ditekshen
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

class BlackRATMutexes(Signature):
    name = "blackrat_mutexes"
    description = "Creates BlackRemote/BlackRAT RAT mutexes"
    severity = 3
    categories = ["RAT"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            "^[A-Za-z]SIL[A-Z0-9a-z]{8,}$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class BlackRATRegistryKeys(Signature):
    name = "blackrat_registry_keys"
    description = "Creates or accesses BlackRemote/BlackRAT RAT registry keys"
    severity = 3
    categories = ["RAT"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RegSetValueExW", "RegQueryValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.score = int()
        self.regpat = re.compile(u'^HKEY_CURRENT_USER\\\\[\x00-\xFF]{0,500}[^\x00-\x7F]{1,}', re.UNICODE)

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExW":
            buff = self.get_argument(call, "Buffer")
            value = self.get_argument(call, "ValueName")
            name = self.get_argument(call, "FullName")
            if value and buff and name:
                if value == "ID" and buff == "HVNC":
                    self.match = True
                elif value == "ID" and re.match(self.regpat, name):
                    self.match = True

        if call["api"] == "RegQueryValueExW":
            data = self.get_argument(call, "Data")
            value = self.get_argument(call, "ValueName")
            name = self.get_argument(call, "FullName")
            if value and data and name:
                if value == "ID" and data == "HVNC":
                    self.match = True
                elif value == "ID" and re.match(self.regpat, name):
                    self.match = True
    
    def on_complete(self):
        return self.match

class BlackRATNetworkActivity(Signature):
    name = "blackrat_network_activity"
    description = "Establishes BlackRemote/BlackRAT RAT network activity"
    severity = 3
    categories = ["RAT"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["send"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    def on_call(self, call, process):
        if call["api"] == "send":
            buff = self.get_argument(call, "buffer")
            if buff:
                if "x00>Clientx, Version=" in buff:
                    self.match = True
    
    def on_complete(self):
        return self.match


class BlackRATAPIs(Signature):
    name = "blackrat_apis"
    description = "Exhibits behavior characteristics of BlackRemote/BlackRAT RAT"
    severity = 3
    categories = ["RAT"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer", "CreateProcessInternalW", "CryptHashData"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptmz = False
        self.rtldecmz = False
        self.score = int()
        self.msbuild = re.compile(".*\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\MSBuild.exe$")
        self.regasm = re.compile(".*\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegAsm.exe$")

    def on_call(self, call, process):
        if call["api"] == "RtlDecompressBuffer":
            ubuff = self.get_argument(call, "UncompressedBuffer")
            if ubuff:
                if ubuff.startswith("MZ"):
                    self.rtldecmz = True
                    self.score += 1

        if call["api"] == "CreateProcessInternalW":
            appname = self.get_argument(call, "ApplicationName")
            if appname:
                if re.match(self.msbuild, appname) or re.match(self.regasm, appname):
                    flags = self.get_argument(call, "CreationFlags")
                    # CREATE_SUSPENDED|CREATE_NO_WINDOW
                    if flags & 0x08000004:
                        self.score += 2
        
        if call["api"] == "CryptHashData":
            buff = self.get_argument(call, "Buffer")
            if buff:
                if buff.startswith("MZ"):
                    self.cryptmz = True
                    self.score += 1
                if buff == "Nativ3M3thodsKey":
                    self.score += 1

    def on_complete(self):
        if self.rtldecmz and self.cryptmz and self.score > 3:
            return True

        return False