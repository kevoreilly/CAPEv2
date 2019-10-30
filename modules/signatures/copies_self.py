# Copyright (C) 2014-2015 Optiv Inc. (brad.spengler@optiv.com)
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

class CopiesSelf(Signature):
    name = "copies_self"
    description = "Creates a copy of itself"
    severity = 3
    categories = ["persistence"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        if self.results["target"]["category"] != "file":
            return False
        if "PE32" not in self.results["target"]["file"]["type"] and "MS-DOS executable" not in self.results["target"]["file"]["type"]:
            return False
        created_copy = False
        # get the path of the initial monitored executable
        initialpath = None
        initialproc = self.get_initial_process()
        if initialproc:
            initialpath = initialproc["module_path"].lower()
        target_sha1 = self.results["target"]["file"]["sha1"]

        if self.results.get("dropped", []):
            for drop in self.results["dropped"]:
                if drop["sha1"] == target_sha1:
                    for path in drop["guest_paths"]:
                        if initialpath and initialpath != path.lower():
                            self.data.append({"copy" : path})
                            created_copy = True
                    return created_copy
        return created_copy
