# Copyright (C) 2020 ditekshen
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


class LokibotMutexes(Signature):
    name = "lokibot_mutexes"
    description = "Creates Lokibot mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["LokiBot"]
    authors = ["ditekshen"]
    minimum = "1.3"
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "0AF8EB8E6F9835A09B24A4FC",
            "F00BB8D50C3D70845038151E",
            "E8B1F8BD2305C6E88A3BBEE7",
            "AFA8BE3E2615A2343F20F7DA",
            "3749282D282E1E80C56CAE5A",
            "6904A8685FEBEBF9ABE152B4",
            "A80B6387732A0FD3406F7A33",
            "56BC56B24CFE6F2024462707",
            "D4D5A6DF569DD66C39E6EB85",
            "300134BE5A3EACE282B993B6",
            "1502268A94D353619B0F12CA",
            "D39991FDCC72D8CA29A4A0DE",
            "58EB8F4751990E685A8B04A3",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False
