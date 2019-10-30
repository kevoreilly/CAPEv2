# Copyright (C) 2019 Kevin Ross
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

class PersistenceShimDatabase(Signature):
    name = "persistence_shim_database"
    description = "Registers an application compatibility shim database for persistence"
    severity = 3
    confidence = 50
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    references = ["https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html", "https://countercept.com/blog/hunting-for-application-shim-databases/"]
    ttp = ["T1138"]

    def run(self):
        ret = False
        reg_indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\Windows\\ NT\\\\CurrentVersion\\\\AppCompatFlags\\\\Custom.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\Windows\\ NT\\\\CurrentVersion\\\\AppCompatFlags\\\\InstalledSDB.*",
        ]

        file_indicators = [
            ".*\\\\Windows\\\\AppPatch\\\\Custom\\\\Custom64\\\\.*\.sdb$",
        ]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                ret = True
                self.data.append({"regkey": match })

        for indicator in file_indicators:
            match = self.check_write_file(pattern=indicator, regex=True, all=True)
            if match:
                ret = True
                self.data.append({"file": match })

        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "sdbinst" in lower:
                ret = True
                self.data.append({"cmdline": cmdline })

        return ret
