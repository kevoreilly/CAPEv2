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

class Nymaim_APIs(Signature):
    name = "nymaim_behavior"
    description = "Exhibits behavior characteristic of Nymaim malware"
    weight = 3
    severity = 3
    categories = ["trojan", "ransomware"]
    families = ["nymaim"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.regkey = False
        self.keyname = str()

    filter_apinames = set(["NtCreateKey", "NtSetValueKey"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateKey":
            buf = self.get_argument(call, "ObjectAttributes")
            if buf and buf.startswith("HKEY_CURRENT_USER\\Software\\Microsoft\\") and buf.count("\\") == 3:
                self.keyname = buf

        elif call["api"] == "NtSetValueKey":
            if self.keyname:
                buflen = int(self.get_argument(call, "BufferLength"))
                key = self.get_argument(call, "FullName")
                if buflen and buflen > 2048 and key.startswith(self.keyname):
                    self.regkey = True

    def on_complete(self):
        if self.regkey:
            return True

        return False
