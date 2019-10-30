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

class LimeRATMutexes(Signature):
    name = "limerat_mutexes"
    description = "Creates known LimeRAT RAT mutexes"
    severity = 3
    categories = ["RAT"]
    families = ["LimeRAT"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "0E1513CB5D0B",
            "3862E8D73699",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class LimeRATRegkeys(Signature):
    name = "limerat_regkeys"
    description = "Creates known LimeRAT RAT registry keys"
    severity = 3
    categories = ["RAT"]
    families = ["LimeRAT"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "HKEY_CURRENT_USER\\\\Software\\\\3862E8D73699\\\\Flood$",
            "HKEY_CURRENT_USER\\\\Software\\\\3862E8D73699\\\\Rans-Status$",
            "HKEY_CURRENT_USER\\\\Software\\\\0E1513CB5D0B\\\\Flood$",
            "HKEY_CURRENT_USER\\\\Software\\\\0E1513CB5D0B\\\\Rans-Status$",
        ]

        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False 