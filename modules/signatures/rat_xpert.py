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


class XpertRATMutexes(Signature):
    name = "xpertrat_mutexes"
    description = "XpertRAT RAT mutexes detected"
    severity = 3
    categories = ["rat"]
    families = ["XpertRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "^G2L6E3O1-E775-G5J4-R4C2-P5F660S1R4A8$",
            "^H0U2K1E4-X5W2-F3C0-W441-A6P5N3Y338D1$",
            "^G2G228Q5-P8H1-G1U7-U4L6-D1K007E3Y0Y8$",
            "^Q0V4O1A8-O5N3-X331-D1M0-A2W3Q6D8C2R6$",
            "^L7N5H8T1-D8F4-W0G0-J2H6-T8S8Y5H224P8$",
            "^D7X4P1B8-Q5O3-S1E1-N0C3-X4R7E8E2T6P3$",
        ]

        for indicator in indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.data.append({"mutex": match_mutex})
                return True

        return False


class XpertRATFiles(Signature):
    name = "xpertrat_files"
    description = "XpertRAT RAT files detected"
    severity = 3
    categories = ["rat"]
    families = ["XpertRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0001", "C0016"]  # micro-behaviour

    def run(self):
        score = 0
        indicators = list()
        user = self.get_environ_entry(self.get_initial_process(), "UserName")
        guid = "[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}"

        try:
            indicators.append(".*\\\\AppData\\\\Local\\\\Temp\\\\" + user.decode("utf-8") + "\.bmp")
        except Exception:
            return False

        indicators.append(".*\\\\AppData\\\\Roaming\\\\" + guid + "\\\\ut$")
        indicators.append(".*\\\\AppData\\\\Roaming\\\\" + guid + "\\\\" + guid + "\.(exe|pas)")

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score >= 2:
            return True

        return False
