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


class CRATMutexes(Signature):
    name = "crat_mutexes"
    description = "CRAT RAT mutex detected"
    severity = 3
    categories = ["rat"]
    families = ["CRAT"]
    authors = ["ditekshen"]
    minimum = "2.0"
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "^CRAT$",
            "CratKeyLog2Mutex",
            "CratScreenCaptureMutex",
            "CratClipboardMonitor2Mutex",
            "^CRAT\d+\.\d+\.\d+\.\d+$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False
