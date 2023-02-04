# Copyright (C) 2021 bartblaze
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


class DisablesWindowsFileProtection(Signature):
    name = "disables_windows_file_protection"
    description = "Attempts to disable Windows File Protection aka System File Checker."
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.2"

    def run(self):
        ret = False

        keys = [
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\SFCDisable$",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\SFCScan$",
        ]

        for check in keys:
            match = self.check_write_key(pattern=check, regex=True)
            if match:
                self.data.append({"regkey": match})
                ret = True

        return ret
