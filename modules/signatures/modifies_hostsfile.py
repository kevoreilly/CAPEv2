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

class Modifies_HostFile(Signature):
    name = "modifies_hostfile"
    description = "The sample wrote data to the system hosts file."
    severity = 3
    categories = ["misc"]
    authors = ["KillerInstinct"]
    minimum = "1.2"

    def run(self):
        ret = False
        match = self.check_write_file(pattern=".*\\\\Windows\\\\(System32|SysWow64)\\\\drivers\\\\etc\\\\hosts$", regex=True)
        if match:
            ret = True
            hfile = match.lower()
            data = ""
            if "dropped" in self.results:
                for dfile in self.results["dropped"]:
                    if hfile in map(str.lower, dfile["guest_paths"]):
                        with open(dfile["path"], "r") as rfile:
                            data = rfile.read()
                        break
                if data:
                    for line in data.split("\r\n"):
                        if not line.startswith("#") and len(line) > 4:
                            self.data.append({"added": line})

        return ret
