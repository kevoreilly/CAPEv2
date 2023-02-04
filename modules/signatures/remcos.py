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


class RemcosFiles(Signature):
    name = "remcos_files"
    description = "Creates known Remcos directories and/or files"
    severity = 3
    categories = ["rat"]
    families = ["Remcos"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0001", "C0016"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\AppData\\\\Roaming\\\\[Ll]ogs\\\\.*\.dat$",
            ".*\\\\AppData\\\\Roaming\\\\remcos.*",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False


class RemcosMutexes(Signature):
    name = "remcos_mutexes"
    description = "Creates known Remcos mutexes"
    severity = 3
    categories = ["rat"]
    families = ["Remcos"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "Remcos_Mutex_Inj",
            "Remcos-[A-Z0-9]{6}$",
            "remcos[-_].*",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True, all=True)
            if match:
                for rematch in match:
                    self.data.append({"mutex": rematch})
                return True

        return False


class RemcosRegkeys(Signature):
    name = "remcos_regkeys"
    description = "Creates known Remcos registry keys"
    severity = 3
    categories = ["rat"]
    families = ["Remcos"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1112", "T1219"]  # MITRE v6,7,8
    mbcs = ["B0022", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\Software\\\\Remcos-[A-Z0-9]{6}.*",
            ".*\\\\Software\\\\remcos[-_].*",
        ]

        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
