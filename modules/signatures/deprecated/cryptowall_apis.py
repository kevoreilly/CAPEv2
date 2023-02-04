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


class CryptoWall_APIs(Signature):
    name = "cryptowall_behavior"
    description = "Exhibits behavior characteristic of Cryptowall ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["CryptoWall"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]
    mbcs += ["OC0005", "C0027"]  # micro-behaviour

    filter_apinames = set(["CryptHashData", "RtlDecompressBuffer", "NtOpenEvent"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptInfo = False
        self.campaign = str()
        self.buffers = set()
        self.lastLargeBuf = str()
        self.compname = self.get_environ_entry(self.get_initial_process(), "ComputerName")

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            buf = self.get_argument(call, "Buffer")
            if buf:
                if len(buf) > 512:
                    self.lastLargeBuf = buf
                if self.cryptInfo and buf.startswith("crypt"):
                    if not self.campaign:
                        self.campaign = buf.split("00")[0]
                        if self.pid:
                            self.mark_call()
                else:
                    buf = buf.replace("\\x00", "")
                    if self.compname and buf.startswith(self.compname):
                        self.cryptInfo = True
                        if self.pid:
                            self.mark_call()
                    else:
                        self.cryptInfo = False

        elif call["api"] == "RtlDecompressBuffer":
            if self.campaign:
                buf = self.get_argument(call, "UncompressedBuffer")
                if buf:
                    self.buffers.add(buf)
                    if self.pid:
                        self.mark_call()

        elif call["api"] == "NtOpenEvent":
            eventName = self.get_argument(call, "EventName")
            if eventName and eventName.startswith("\\BaseNamedObjects\\"):
                bno = eventName.split("\\")[-1]
                if bno and bno in self.lastLargeBuf:
                    idx = self.lastLargeBuf.find(bno)
                    self.campaign = self.lastLargeBuf[0:idx]
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        if self.campaign:
            self.data.append({"Campaign": self.campaign})
            if self.buffers:
                c2s = list()
                pat = r"(?:https?:\/\/)?(?:[\da-z\.-]+)\.(?:[0-9a-z\.]{2,6})(?:\d{1,5})?(?:[\/\w\.-]*)\/?"
                for buf in self.buffers:
                    curC2 = buf.split(r"\x00")
                    if curC2:
                        for c2 in curC2:
                            if len(c2) > 6 and re.match(pat, c2):
                                c2s.append(c2)
                if c2s:
                    for c2 in c2s:
                        tmp = {"c2": c2}
                        if tmp not in self.data:
                            self.data.append(tmp)

            return True

        return False
