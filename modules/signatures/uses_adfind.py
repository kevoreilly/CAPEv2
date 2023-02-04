# Copyright (C) 2020 bartblaze
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


class ADFind(Signature):
    name = "uses_adfind"
    description = "Queries the Active Directory using AdFind"
    severity = 3
    categories = ["discovery"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["S0552"]  # MITRE
    ttps += ["T1069"]  # MITRE v6,7,8
    references = ["http://www.joeware.net/freetools/tools/adfind/"]

    def run(self):
        utilities = [
            "adfind ",
            "adfind.exe",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command": cmdline})

        return ret
