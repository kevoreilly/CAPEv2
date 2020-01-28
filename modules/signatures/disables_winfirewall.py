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

class DisablesWindowsFirewall(Signature):
    name = "disables_winfirewall"
    description = "Disables Windows firewall"
    severity = 3
    categories = ["generic"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttp = ["T1089"]

    def run(self):
        indicators = [
            "netsh\s+firewall\s+set.*disable",
            "netsh\s+advfirewall\s+set.*off",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True, all=True)
            if match:
                for fwcmd in match:
                    self.data.append({"command": fwcmd})
                return True

        return False