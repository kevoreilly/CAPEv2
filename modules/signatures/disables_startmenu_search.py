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


class DisablesStartMenuSearch(Signature):
    name = "disables_startmenu_search"
    description = "Disables host Start Menu search"
    severity = 2
    categories = ["ransomware"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\NoSearchFilesInStartMenu",
            "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\NoSearchProgramsInStartMenu",
            "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\NoStartMenuMorePrograms",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
