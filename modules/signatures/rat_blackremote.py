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
    categories = ["rat"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0003", "C0042"]  # micro-behaviour

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
    categories = ["rat"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112", "T1219"]  # MITRE v6,7,8
    mbcs = ["B0022", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    filter_apinames = set(["RegSetValueExW", "RegQueryValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.score = int()
        self.regpat = re.compile("^HKEY_CURRENT_USER\\\\[\x00-\xFF]{0,500}[^\x00-\x7F]{1,}", re.UNICODE)

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExW":
            buff = self.get_argument(call, "Buffer")
            value = self.get_argument(call, "ValueName")
            name = self.get_argument(call, "FullName")
            if value and buff and name:
                if value == "ID" and buff == "HVNC":
                    if self.pid:
                        self.mark_call()
                    self.match = True
                elif value == "ID" and re.match(self.regpat, name):
                    if self.pid:
                        self.mark_call()
                    self.match = True

        if call["api"] == "RegQueryValueExW":
            data = self.get_argument(call, "Data")
            value = self.get_argument(call, "ValueName")
            name = self.get_argument(call, "FullName")
            if value and data and name:
                if value == "ID" and data == "HVNC":
                    if self.pid:
                        self.mark_call()
                    self.match = True
                elif value == "ID" and re.match(self.regpat, name):
                    if self.pid:
                        self.mark_call()
                    self.match = True

    def on_complete(self):
        return self.match


class BlackRATNetworkActivity(Signature):
    name = "blackrat_network_activity"
    description = "Establishes BlackRemote/BlackRAT RAT network activity"
    severity = 3
    categories = ["rat"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs = ["B0022"]
    mbcs += ["OC0006", "C0001"]  # micro-behaviour

    filter_apinames = set(["send"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    def on_call(self, call, process):
        if call["api"] == "send":
            buff = self.get_argument(call, "buffer")
            if buff:
                if "x00>Clientx, Version=" in buff:
                    if self.pid:
                        self.mark_call()
                    self.match = True

    def on_complete(self):
        return self.match


class BlackRATAPIs(Signature):
    name = "blackrat_apis"
    description = "Exhibits behavior characteristics of BlackRemote/BlackRAT RAT"
    severity = 3
    categories = ["rat"]
    families = ["BlackRAT", "BlackRemote"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

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
            if ubuff and ubuff.startswith("MZ"):
                if self.pid:
                    self.mark_call()
                self.rtldecmz = True
                self.score += 1

        if call["api"] == "CreateProcessInternalW":
            appname = self.get_argument(call, "ApplicationName")
            if appname:
                if re.match(self.msbuild, appname) or re.match(self.regasm, appname):
                    flags = int(self.get_argument(call, "CreationFlags"), 16)
                    # CREATE_SUSPENDED|CREATE_NO_WINDOW
                    if flags & 0x4 or flags & 0x08000004:
                        if self.pid:
                            self.mark_call()
                        self.score += 2

        if call["api"] == "CryptHashData":
            self.mbcs += ["OC0005", "C0027"]  # micro-behaviour
            buff = self.get_argument(call, "Buffer")
            if buff:
                if buff.startswith("MZ"):
                    if self.pid:
                        self.mark_call()
                    self.cryptmz = True
                    self.score += 1
                if buff == "Nativ3M3thodsKey":
                    if self.pid:
                        self.mark_call()
                    self.score += 1

    def on_complete(self):
        if self.rtldecmz and self.cryptmz and self.score > 3:
            return True

        return False
