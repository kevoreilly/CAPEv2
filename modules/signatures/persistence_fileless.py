# Copyright (C) 2018 Kevin Ross
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

class PersistenceRegistryScript(Signature):
    name = "persistence_registry_script"
    description = "Stores JavaScript or a script command in the registry, likely for fileless persistence"
    severity = 3
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttp = ["T1112"]
    
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.scripts = [
            "cscript",
            "hta ",
            "hta.exe",
            "javascript:",
            "powershell",
            "wscript",
        ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        fullname = self.get_argument(call, "FullName")
        buf = self.get_argument(call, "Buffer")
        for script in self.scripts:
            if buf and script in buf.lower():
                self.registry_writes[fullname] = buf

    def on_complete(self):
        ret = False
        for key, value in self.registry_writes.iteritems():
            self.data.append({"key" : key})
            self.data.append({"data" : value})
            ret = True

        return ret
