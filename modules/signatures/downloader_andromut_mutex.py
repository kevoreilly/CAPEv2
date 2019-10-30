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

# Samples:
# 1e93369a67b0bf1d4d3b276b4598b0900c45fb62525fc31a9f7d4bbfa1f134f6
# 2d5f65692687646e5e11c7563ded4c1a7f534041b2a455ed66aaea4a546e67c4
# 1d91e3f97ffb4905de37e78b3a7d3a9db06b3b521a04b2536eab4212d30a3da4
# 939fc27e436ee7217d027d4ac1f1f136372863145b58cf882636049df17fdc03

from lib.cuckoo.common.abstracts import Signature

class AndromutMutexes(Signature):
    name = "andromut_mutexes"
    description = "Creates known Andromut mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["Andromut"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "mutshell"
            "mutshellmy",
            "mutshellmy\d+",
        ]

        for indicator in indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.data.append({"mutex": match_mutex})
                return True

        return False