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

class Dropper(Signature):
    name = "dropper"
    description = "Drops a binary and executes it"
    severity = 2
    confidence = 50
    categories = ["dropper"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1129"]

    def run(self):
        is_dropper = False
        mainprocesspath = ""
        processpaths = set()
        processes = None
        if "behavior" in self.results and "processes" in self.results["behavior"]:
            processes = self.results["behavior"]["processes"]
        if processes and len(processes):
            mainprocesspath = processes[0]["module_path"].lower()
            for process in processes[1:]:
                processpath = process["module_path"].lower()
                if processpath != mainprocesspath:
                    processpaths.add(processpath)
        for processpath in processpaths:
            for drop in self.results["dropped"]:
                for path in drop["guest_paths"]:
                    if path.lower() == processpath:
                        self.data.append({"binary" : path})
                        is_dropper = True
                        if self.results["info"]["package"] not in ["exe", "bin", "msi", "rar", "zip", "dll", "regsvr"]:
                            self.severity = 3
        return is_dropper
