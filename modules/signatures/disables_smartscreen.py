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


class DisablesSmartScreen(Signature):
    name = "disables_smartscreen"
    description = "Modifies or disables Windows SmartScreen"
    severity = 3
    categories = ["generic"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v7,8
    ttps += ["T1562", "T1562.001"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112", "F0004"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        re_match = False
        cmd_match = False
        indicators = [
            ".*\\\\Windows\\\\CurrentVersion\\\\explorer\\\\SmartScreenEnabled$",
            ".*\\\\Windows\\\\CurrentVersion\\\\AppHost\\\\SmartScreenEnabled$",
            ".*\\\\MicrosoftEdge\\\\PhishingFilter$",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                re_match = True

        cmdpat = '.*"SmartScreenEnabled".*"Off".*'
        match = self.check_executed_command(pattern=cmdpat, regex=True)
        if match:
            self.data.append({"command": match})
            cmd_match = True

        if re_match or cmd_match:
            return True

        return False
