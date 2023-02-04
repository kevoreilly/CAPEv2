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


class SpicyHotPotBehavior(Signature):
    name = "spicyhotpot_behavior"
    description = "SpicyHotPot browser hijacking rootkit artificats detected"
    severity = 3
    categories = ["rootkit"]
    families = ["SpicyHotPot"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1014"]  # MITRE v6,7,8
    mbcs = ["E1014"]

    def run(self):
        score = 0
        indicators = ["DLreport", "Update", "DVLayout", "dumping"]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=False)
            if match:
                score += 1
                self.data.append({"mutex": match})

        indicators = [
            ".*\\\\Microsoft\\\\(WindowsApps|Media\sPlayer)\\\\(KMDF_LOOK|KMDF_Protect)\.sys",
            ".*\\\\Microsoft\\\\Event\sViewer\\\\(wccenter|wdlogin|wrme|wuhost)\.exe",
        ]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        # uncomment after check_created_service is available
        # indicators = [
        #    "iaLPSS1z",
        #    "LSI_SAS2l",
        # ]

        # for indicator in indicators:
        #    match = self.check_created_service(pattern=indicator, regex=False)
        #    if match:
        #        score += 1
        #        self.data.append({"service": match})

        if score > 1:
            return True

        return False
