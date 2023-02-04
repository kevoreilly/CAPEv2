# Copyright (C) 2015 Optiv Inc. (brad.spengler@optiv.com)
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


class CreatesLargeKey(Signature):
    name = "creates_largekey"
    description = "Creates or sets a registry key to a long series of bytes, possibly to store a binary or malware config"
    severity = 3
    confidence = 80
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112", "OB0012"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    filter_apinames = set(["NtSetValueKey", "RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.saw_large = False
        self.regkeyvals = set()

    def on_call(self, call, process):
        vallen = self.get_argument(call, "BufferLength")
        if vallen:
            length = int(vallen)
            if length > 16 * 1024:
                self.regkeyvals.add(self.get_argument(call, "FullName"))
                if self.pid:
                    self.mark_call()
                self.saw_large = True

    def on_complete(self):
        if self.saw_large:
            for keyval in self.regkeyvals:
                self.data.append({"regkeyval": keyval})
        return self.saw_large
