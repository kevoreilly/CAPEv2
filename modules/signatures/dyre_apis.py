# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), KillerInstinct
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

class Dyre_APIs(Signature):
    name = "dyre_behavior"
    description = "Exhibits behavior characteristic of Dyre malware"
    weight = 3
    severity = 3
    categories = ["banker", "trojan"]
    families = ["dyre"]
    authors = ["Optiv", "KillerInstinct"]
    minimum = "1.3"
    evented = True
    # Try to parse a process memory dump to extract regex extract C2 nodes.
    extract_c2s = True


    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptoapis = False
        self.networkapis = set()
        self.syncapis = False
        self.compname = self.get_environ_entry(self.get_initial_process(),
                                               "ComputerName")

    filter_apinames = set(["CryptHashData", "HttpOpenRequestA",
                           "NtCreateNamedPipeFile"])

    def on_call(self, call, process):
        # Legacy, modern Dyre doesn't have hardcoded hashes in
        # CryptHashData anymore
        iocs = [
            "J7dnlDvybciDvu8d46D\\x00",
            "qwererthwebfsdvjaf+\\x00",
        ]
        pipe = [
            "\\??\\pipe\\3obdw5e5w4",
            "\\??\\pipe\\g2fabg5713",
        ]
        if call["api"] == "CryptHashData":
            buf = self.get_argument(call, "Buffer")
            if buf in iocs:
                self.cryptoapis = True
            tmp = re.sub(r"\\x[0-9A-Fa-f]{2}", "", buf)
            if self.compname in tmp:
                if re.match("^" + self.compname + "[0-9 ]+$", tmp):
                    self.cryptoapis = True
        elif call["api"] == "HttpOpenRequestA":
            buf = self.get_argument(call, "Path")
            if len(buf) > 10:
                self.networkapis.add(buf)
        elif call["api"] == "NtCreateNamedPipeFile":
            buf = self.get_argument(call, "PipeName")
            for npipe in pipe:
                if buf == npipe:
                    self.syncapis = True
                    break

        return None

    def on_complete(self):
        ret = False
        networkret = False
        campaign = set()
        mutexs = [
            "^(Global|Local)\\\\pen3j3832h$",
            "^(Global|Local)\\\\u1nyj3rt20",
        ]
        for mutex in mutexs:
            if self.check_mutex(pattern=mutex, regex=True):
                self.syncapis = True
                break

        # C2 Beacon check
        if self.networkapis:
            # Gather computer name
            for httpreq in self.networkapis:
                # Generate patterns (should only ever be one per indicator)
                indicators = [
                    "/(\d{4}[a-z]{2}\d{2})/" + self.compname + "_",
                    "/([^/]+)/" + self.compname + "/\d+/\d+/\d+/$",
                    "/([^/]+)/" + self.compname + "_W\d{6}\.[0-9A-F]{32}",
                ]
                for indicator in indicators:
                    buf = re.match(indicator, httpreq)
                    if buf:
                        networkret = True
                        campaign.add(buf.group(1))

        # Check if there are any winners
        if self.cryptoapis or self.syncapis or networkret:
            ret = True
            if (self.cryptoapis or self.syncapis) and networkret:
                self.confidence = 100
                self.description = "Exhibits behaviorial and network characteristics of Upatre+Dyre/Mini-Dyre malware"
                for camp in campaign:
                    self.data.append({"Campaign": camp})

            elif networkret:
                self.description = "Exhibits network behavior characteristic of Upatre+Dyre/Mini-Dyre malware"
                for camp in campaign:
                    self.data.append({"Campaign": camp})

            if self.extract_c2s:
                dump_pid = 0
                for proc in self.results["behavior"]["processtree"]:
                    for child in proc["children"]:
                        # Look for lowest PID svchost.exe
                        if not dump_pid or child["pid"] < dump_pid:
                            if child["name"] == "svchost.exe":
                                dump_pid = child["pid"]
                if dump_pid:
                    dump_path = ""
                    if len(self.results["procmemory"]):
                        for memdump in self.results["procmemory"]:
                            if dump_pid == memdump["pid"]:
                                dump_path = memdump["file"]
                    if dump_path:
                        whitelist = [
                            "1.2.3.4",
                            "0.0.0.0",
                        ]
                        with open(dump_path, "rb") as dump_file:
                            dump_data = dump_file.read()
                        ippat = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}"
                        ips = re.findall(ippat, dump_data)
                        for ip in set(ips):
                            addit = True
                            for item in whitelist:
                                if ip.startswith(item):
                                    addit = False
                            if addit:
                                self.data.append({"C2": ip})

        return ret
