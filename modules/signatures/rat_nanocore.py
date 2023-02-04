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


class NanocoreRAT(Signature):
    name = "rat_nanocore"
    description = "Exhibits behavior characteristic of Nanocore RAT"
    weight = 3
    severity = 3
    categories = ["rat"]
    families = ["NanoCore"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

    filter_apinames = set(["CryptHashData"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptcalls = 0
        self.cryptmz = 0

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            self.mbcs += ["OC0005", "C0027"]  # micro-behaviour
            buf = self.get_argument(call, "Buffer")
            if buf:
                tail = "6" * 48
                if buf.endswith(tail):
                    self.cryptcalls += 1
                    if self.pid:
                        self.mark_call()
                if buf.startswith("MZ"):
                    self.cryptmz += 1
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        badness = 0
        guid = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}" "-[0-9a-fA-F]{12}"
        fileiocs = [
            ".*\\\\" + guid + "\\\\run\.dat$",
            ".*\\\\" + guid + "\\\\task\.dat$",
            ".*\\\\" + guid + "\\\\catelog\.dat$",
            ".*\\\\" + guid + "\\\\storage\.dat$",
            ".*\\\\" + guid + "\\\\settings\.bin$",
        ]
        for ioc in fileiocs:
            if self.check_write_file(pattern=ioc, regex=True):
                self.mbcs += ["OC0001", "C0016"]  # micro-behaviour
                badness += 1

        mutex = "(Global|Local)\\\\\{" + guid + "\}$"
        if self.check_mutex(pattern=mutex, regex=True):
            self.mbcs += ["OC0003", "C0042"]  # micro-behaviour
            badness += 1

        if self.cryptmz >= 2 and self.cryptcalls:
            if self.cryptcalls > 4:
                self.cryptcalls = 4
            badness += self.cryptcalls

        if badness >= 5:
            return True

        return False
