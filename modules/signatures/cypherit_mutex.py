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

class CypherITMutexes(Signature):
    name = "cypherit_mutexes"
    description = "Creates known CypherIT/Frenchy Shellcode mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["AgentTesla", "HawkEye", "Nanocore", "Formbook", "Remcos", "Njrat", "Azorult", "Fareit", "Lokibot", "Predator"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttp = ["T1045"]

    def run(self):
        indicators = [
            "frenchy_shellcode_\d+$",
            "Startup_shellcode_\d+$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True, all=True)
            if match:
                for mut in match:
                    self.data.append({"mutex": mut})
                return True

        return False