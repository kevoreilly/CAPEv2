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


class QulabMutexes(Signature):
    name = "qulab_mutexes"
    description = "Creates Qulab/MASAD information stealer mutexes"
    severity = 3
    categories = ["infostealer"]
    families = ["Qulab", "MASAD"]
    authors = ["ditekshen"]
    minimum = "1.3"
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "^[0-9]{8,10}ENU_[A-F0-9]{20}$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False


class QulabFiles(Signature):
    name = "qulab_files"
    description = "Creates Qulab/MASAD information stealer files"
    severity = 3
    categories = ["infostealer"]
    families = ["Qulab", "MASAD"]
    authors = ["ditekshen"]
    minimum = "1.3"
    mbcs = ["OC0001", "C0016"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\(x86|amd6)_microsoft-windows-.*\\\\(Screen\.jpg|Information\.txt|ShortInformation\.txt)$",
            ".*\\\\(x86|amd6)_microsoft-windows-.*\\\\Desktop\sTXT\sFiles\\\\.*",
            ".*\\\\(x86|amd6)microsoft-windows-.*\\\\.*sqlite3\.module\.dll$",
            ".*\\\\(x86|amd6)microsoft-windows-.*\\\\ENU_[A-F0-9]{20}$",
        ]
        score = 0

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score >= 2:
            return True

        return False
