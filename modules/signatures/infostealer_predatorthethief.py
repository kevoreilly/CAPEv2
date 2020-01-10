# Copyright (C) 2019 ditekshen
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

# References:
# https://any.run/malware-trends/predator
# https://securelist.com/a-predatory-tale/89779/
# https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/

from lib.cuckoo.common.abstracts import Signature

class PredatorTheThiefMutexes(Signature):
    name = "predatorthethief_mutexes"
    description = "Creates Predator The Thief information stealer mutexes"
    severity = 3
    categories = ["infostealer"]
    families = ["PredatorTheThief"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "SyystemServs",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class PredatorTheThiefFiles(Signature):
    name = "predatorthethief_files"
    description = "Creates Predator The Thief information stealer files"
    severity = 3
    categories = ["infostealer"]
    families = ["PredatorTheThief"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\\\\vlmi\{lulz\}yg\.col$",
            ".*\\\\forms\.(log|txt)$",
            ".*\\\\cards\.(log|txt)$",
            ".*\\\\password\.(log|txt)$",
            ".*\\\\Information\.(log|txt)$",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
