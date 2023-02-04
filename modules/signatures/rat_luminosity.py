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

from lib.cuckoo.common.abstracts import Signature


class LuminosityRAT(Signature):
    name = "rat_luminosity"
    description = "Exhibits behavior characteristic of Luminosity Link RAT"
    weight = 3
    severity = 3
    categories = ["rat"]
    families = ["Luminosity"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

    filter_apinames = set(["CryptHashData", "NtCreateFile", "NtCreateMutant"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.chars = "0123456789ABCDEFabcdef"
        self.crypthash = str()
        self.filehit = False
        self.mutexhit = False
        self.lastapi = str()

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            self.mbcs += ["OC0005", "C0027"]  # micro-behaviour
            buf = self.get_argument(call, "Buffer")
            if buf and len(buf) <= 64 and len(buf) >= 32:
                if all((c in self.chars) for c in buf):
                    self.crypthash = buf
                    if self.pid:
                        self.mark_call()

        elif call["api"] == "NtCreateFile":
            if self.lastapi == "CryptHashData":
                self.mbcs += ["OC0001", "C0016"]  # micro-behaviour
                buf = self.get_argument(call, "FileName")
                if buf and self.crypthash and self.crypthash in buf:
                    self.filehit = True
                    if self.pid:
                        self.mark_call()

        elif call["api"] == "NtCreateMutant":
            if self.lastapi == "CryptHashData":
                self.mbcs += ["OC0003", "C0042"]  # micro-behaviour
                buf = self.get_argument(call, "MutexName")
                if buf and self.crypthash and self.crypthash in buf:
                    self.mutexhit = True
                    if self.pid:
                        self.mark_call()

        self.lastapi = call["api"]

    def on_complete(self):
        if self.filehit and self.mutexhit:
            return True

        return False
