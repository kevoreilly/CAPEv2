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

from lib.cuckoo.common.abstracts import Signature


class ThemidaPacked(Signature):
    name = "packer_themida"
    description = "An executed process used known Themida API calls."
    severity = 3
    categories = ["packer", "anti-debug"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    ttps = ["T1045"]  # MITRE v6
    ttps += ["T1027"]  # MITRE v6,7,8
    ttps += ["T1027.002"]  # MITRE v7,8
    mbcs = ["OB0001", "OB0002", "OB0006", "F0001", "F0001.011"]

    filter_apinames = set(["FindWindowA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = dict()

    def on_call(self, call, process):
        indicators = [
            "OLLYDBG",
            "GBDYLLO",
            "pediy06",
            "FilemonClass",
            "File Monitor - Sysinternals: www.sysinternals.com",
            "PROCMON_WINDOW_CLASS",
            "Process Monitor - Sysinternals: www.sysinternals.com",
            "RegmonClass",
            "Registry Monitor - Sysinternals: www.sysinternals.com",
            "18467-41",
        ]
        pid = str(process["process_id"])
        pname = process["process_name"]
        cname = self.get_argument(call, "ClassName")
        wname = self.get_argument(call, "WindowName")
        if pid not in self.ret.keys():
            self.ret[pid] = dict()
            self.ret[pid]["process"] = pname
            self.ret[pid]["apivalues"] = list()
        if cname and cname != "0" and cname in indicators:
            if cname not in self.ret[pid]["apivalues"]:
                self.ret[pid]["apivalues"].append(cname)
                if self.pid:
                    self.mark_call()
        if wname and wname != 0 and wname in indicators:
            if wname not in self.ret[pid]["apivalues"]:
                self.ret[pid]["apivalues"].append(wname)
                if self.pid:
                    self.mark_call()
        return None

    def on_complete(self):
        hit = False
        themidaprocs = list()
        if self.ret:
            for proc in self.ret.keys():
                if len(self.ret[proc]["apivalues"]) >= 8:
                    themidaprocs.append(self.ret[proc]["process"])

            if len(themidaprocs) > 0:
                hit = True
                procs = ", ".join(themidaprocs)
                self.description = "The following process appear to have been packed with Themida: " + procs

        return hit


class ThemidaPackedSection(Signature):
    name = "packer_themida"
    description = "Executable file is packed/obfuscated with Themida"
    severity = 2
    categories = ["packer"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttps = ["T1045"]  # MITRE v6
    ttps += ["T1027"]  # MITRE v6,7,8
    ttps += ["T1027.002"]  # MITRE v7,8
    mbcs = ["OB0001", "OB0002", "OB0006", "F0001", "F0001.011"]

    def run(self):
        for section in self.results.get("static", {}).get("pe", {}).get("sections", []):
            if section["name"].lower().startswith(".themida"):
                self.data.append({"section": section})
                return True

        return False
