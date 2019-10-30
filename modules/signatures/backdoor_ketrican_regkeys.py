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

class KetricanRegkeys(Signature):
    name = "ketrican_regkeys"
    description = "Interacts with known Ke3chang Ketrican / Tidepool / BS2005 registry keys"
    severity = 3
    categories = ["backdoor"]
    families = ["Ketrican"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        score = 0
        indicators = [
            ".*\\\\Software\\\\Microsoft\\\\Internet\ Explorer\\\\Main\\\\Check_Associations",
            ".*\\\\Software\\\\Microsoft\\\\Internet\ Explorer\\\\Main\\\\DisableFirstRunCustomize",
            ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\ Settings\\\\ZoneMap\\\\IE[Hh]arden",
        ]

        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True, all=True)
            if match:
                score += 1
                self.data.append({"regkey": match})

        if score >= 3:
            return True
        else:
            return False