# Copyright (C) 2016 KillerInstinct
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

import hashlib
from urlparse import parse_qs, urlparse

from lib.cuckoo.common.abstracts import Signature

class Locky_APIs(Signature):
    name = "Locky_behavior"
    description = "Exhibits behavior characteristic of Locky ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["locky"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    carve_mem = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.checkEvent = False
        self.lastapi = str()
        self.volumes = set()
        self.hashes = set()
        self.found = 0
        self.c2s = set()
        self.payment = set()
        self.keywords = ["id=", "act=", "lang="]
        self.sigchanged = False

    filter_apinames = set(["GetVolumeNameForVolumeMountPointW",
                           "InternetCrackUrlA", "CryptHashData",
                           "NtOpenEvent"])

    def on_call(self, call, process):
        if self.checkEvent and self.lastapi == "CryptHashData":
            if call["api"] == "NtOpenEvent":
                event = self.get_argument(call, "EventName")
                event = event.split("\\")
                if len(event) == 2:
                    if event[1] in self.hashes and event[0] in ["Global", "Local"]:
                        self.found = True

        if call["api"] == "GetVolumeNameForVolumeMountPointW":
            if call["status"]:
                name = self.get_argument(call, "VolumeName")
                if name and len(name) > 10:
                    name = name[10:-1]
                    if name not in self.volumes:
                        self.volumes.add(name)
                        md5 = hashlib.md5(name).hexdigest()[:16].upper()
                        self.hashes.add(md5)

        elif call["api"] == "CryptHashData":
            if self.hashes:
                buf = self.get_argument(call, "Buffer")
                if buf and all(word in buf for word in self.keywords):
                    # Try/Except handles when this behavior changes in the future
                    try:
                        args = parse_qs(urlparse("/?" + buf).query,
                                        keep_blank_values=True)
                    except:
                        self.sigchanged = True
                        self.severity = 1
                        self.description = "Potential Locky ransomware behavioral characteristics observed. (See Note)"
                        self.data.append({"Note": "Unexpected behavior observed for Locky. Please " \
                                                  "report this sample to https://github.com/spende" \
                                                  "rsandbox/community-modified/issues"})

                    if args and "id" in args.keys():
                        if args["id"][0] in self.hashes:
                            self.found = process["process_id"]
                        if "affid" in args:
                            tmp = {"Affid": args["affid"][0]}
                            if tmp not in self.data:
                                self.data.append(tmp)

                elif buf in self.volumes and self.lastapi == "GetVolumeNameForVolumeMountPointW":
                    checkEvent = True

                else:
                    check = re.findall(r"\s((?:https?://)?\w+(?:\.onion|\.tor2web)[/.](?:\w+\/)?)",
                                       buf, re.I)
                    if check:
                        for payment in check:
                            self.payment.add(payment)

        elif call["api"] == "InternetCrackUrlA":
            if self.found and process["process_id"] == self.found:
                url = self.get_argument(call, "Url")
                if url and url.endswith(".php"):
                    self.c2s.add(url)

    def on_complete(self):
        if self.sigchanged:
            return True

        ret = False
        if self.found:
            ret = True
            if self.c2s:
                for c2 in self.c2s:
                    self.data.append({"C2": c2})

            if self.carve_mem:
                if "procmemory" in self.results and self.results["procmemory"]:
                    dump_path = str()
                    for process in self.results["procmemory"]:
                        if process["pid"] == int(self.found):
                            dump_path = process["file"]
                            break

                    if dump_path:
                        with open(dump_path, "rb") as dump_file:
                            cData = dump_file.read()
                        buf = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},[\d.,]+)\x00", cData)
                        if buf:
                            for c2 in buf.group(1).split(","):
                                tmp = {"C2": c2}
                                if tmp not in self.data:
                                    self.data.append(tmp)

            if self.payment:
                for url in self.payment:
                    self.data.append({"Payment": url})

        return ret
