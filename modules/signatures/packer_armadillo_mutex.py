# Copyright (C) 2015 KillerInstinct
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

class ArmadilloMutex(Signature):
    name = "packer_armadillo_mutex"
    description = "Detected Armadillo packer using a known mutex"
    severity = 3
    categories = ["packer"]
    authors = ["KillerInstinct"]
    minimum = "0.5"
    ttp = ["T1045"]

    def run(self):
        indicators = [
            ".*:SIMULATEEXPIRED"
        ]

        ret = False
        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                ret = True

        return ret
