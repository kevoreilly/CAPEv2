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

class MedusaLockerMutexes(Signature):
    name = "medusalocker_mutexes"
    description = "Creates known MedusaLocker ransomware mutexes"
    severity = 3
    categories = ["ransomware"]
    families = ["MedusaLocker"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "\{3E5FC7F9-9A51-4367-9063-A120244FBEC7\}$",
            "\{6EDD6D74-C007-4E75-B76A-E5740995E24C\}$",
            "\{8761ABBD-7F85-42EE-B272-A76179687C63\}$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True, all=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class MedusaLockerRegkeys(Signature):
    name = "medusalocker_regkeys"
    description = "Creates known MedusaLocker ransomware registry keys"
    severity = 3
    categories = ["ransomware"]
    families = ["MedusaLocker"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "HKEY_CURRENT_USER\\\\Software\\\\Medusa",
            "HKEY_CURRENT_USER\\\\Software\\\\Medusa\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True, all=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False