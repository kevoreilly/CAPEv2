# Copyright (C) 2022 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re


class WiperZeroedBytes(Signature):
    name = "wiper_zeroedbytes"
    description = "Overwrites multiple files with zero bytes (hex 00) indicative of a wiper"
    severity = 3
    categories = ["malware", "ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1561"]

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.wipecount = 0
        self.lastfile = ""

    def on_call(self, call, process):
        filepath = self.get_raw_argument(call, "HandleName")
        if filepath != self.lastfile:
            buff = self.get_raw_argument(call, "Buffer").lower()
            regex = re.compile("^[\\x00\.]+$")
            if len(buff) > 30 and regex.match(buff):
                self.lastfile = filepath
                self.wipecount += 1
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        ret = False
        if self.wipecount > 10:
            self.data.append({"number of files wiped": "%s" % (self.wipecount)})
            ret = True

        return ret
