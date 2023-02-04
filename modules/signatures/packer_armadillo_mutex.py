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
    ttps = ["T1045"]  # MITRE v6
    ttps += ["T1027"]  # MITRE v6,7,8
    ttps += ["T1027.002"]  # MITRE v7,8
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [".*:SIMULATEEXPIRED"]

        ret = False
        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                ret = True

        return ret
