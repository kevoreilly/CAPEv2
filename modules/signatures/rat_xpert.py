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

from lib.cuckoo.common.abstracts import Signature

class XpertRATMutexes(Signature):
    name = "xpertrat_mutexes"
    description = "Creates Xpert RAT mutexes"
    severity = 3
    categories = ["RAT"]
    families = ["Xpert"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "G2L6E3O1-E775-G5J4-R4C2-P5F660S1R4A8",
        ]

        for indicator in indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.data.append({"mutex": match_mutex})
                return True

        return False

class XpertRATFiles(Signature):
    name = "xpertrat_files"
    description = "Creates Xpert RAT files"
    severity = 3
    categories = ["RAT"]
    families = ["Xpert"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\\\\ut$",
            ".*\\\\Temp\\\\.*\.bmp"
            ".*\\\\G2L6E3O1-E775-G5J4-R4C2-P5F660S1R4A8$"
        ]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False