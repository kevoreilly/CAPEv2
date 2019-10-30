# Copyright (C) 2016 Kevin Ross
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

class RansomwareRadamant(Signature):
    name = "ransomware_radamant"
    description = "Exhibits behavior characteristic of Radamant ransomware"
    severity = 3
    families = ["radamant"]
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttp = ["T1486"]

    def run(self):
        mutexes = [
            "Radamant_v.*",
            ".*radamantv.*",
        ]

        for mutexes in mutexes:
            if self.check_mutex(pattern=mutexes, regex=True):
                return True

        # Check for creation of Autorun
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\(svchost|DirectX)$", regex=True) and self.check_write_file(pattern=".*\\\\Windows\\\\dirextx.exe$", regex=True):
            return True

        # Check for creation of ransom message file
        if self.check_write_file(pattern=".*\\\\YOUR_FILES.url$", regex=True):
            return True

        return False
