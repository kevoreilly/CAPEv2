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


class ApocalypseStealerFileBehavior(Signature):
    name = "apocalypse_stealer_file_behavior"
    description = "Apocalypse infostealer file modification behavior detected"
    severity = 3
    categories = ["infostealer"]
    families = ["Apocalypse"]
    authors = ["ditekshen"]
    minimum = "2.0"
    evented = True
    ttps = ["T1503"]  # MITRE v6
    ttps += ["T1115"]  # MITRE v6,7,8
    ttps += ["T1555", "T1555.003"]  # MITRE v7,8
    mbcs = ["OB0005", "OB0003"]
    mbcs += ["OC0001", "C0052"]  # micro-behaviour

    def run(self):
        score = 0
        file_indicators = [
            ".*\\\\AppData\\\\Local\\\\Temp\\\\browser(Passwords|Cookies|CreditCards)$",
            ".*\\\\AppData\\\\Roaming\\\\(Google|Firefox)\\\\(Passwords|Cookies)\.txt$",
            ".*\\\\AppData\\\\Roaming\\\\Clipboard.txt$",
        ]

        for indicator in file_indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score >= 3:
            return True

        return False
