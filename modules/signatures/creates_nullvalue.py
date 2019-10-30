# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com)
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

class CreatesNullValue(Signature):
    name = "creates_nullvalue"
    description = "Creates a registry key or value with NUL characters to avoid detection with regedit"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttp = ["T1054", "T1112"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.saw_null = False
        self.regkeyvals = set()
    filter_apinames = set(["NtSetValueKey", "NtCreateKey"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateKey":
            keyname = self.get_argument(call, "ObjectAttributes")
            if "\\x00" in keyname:
                self.regkeyvals.add(keyname)
                self.saw_null = True
        else:
            valuename = self.get_argument(call, "ValueName")
            if "\\x00" in valuename:
                self.regkeyvals.add(self.get_argument(call, "FullName"))
                self.saw_null = True

    def on_complete(self):
        if self.saw_null:
            for keyval in self.regkeyvals:
                self.data.append({"keyval" : keyval})
        return self.saw_null