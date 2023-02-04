# Copyright (C) 2014 @threatlead
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


class XtremeMutexes(Signature):
    name = "rat_xtreme_mutexes"
    description = "Creates known XtremeRAT mutexes"
    severity = 3
    categories = ["rat"]
    families = ["XtremeRAT"]
    authors = ["threatlead", "nex"]
    minimum = "0.5"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0003", "C0042"]  # micro-behaviour
    references = [
        "https://malwr.com/analysis/ZWM4YjI2MzI1MmQ2NDBkMjkwNzI3NzhjNWM5Y2FhY2U/",
        "https://malwr.com/analysis/MWY5YTAwZWI1NDc3NDJmMTgyNDA4ODc0NTk0MWIzNjM/",
    ]

    def run(self):
        indicators = ["XTREMEUPDATE", "\(\(Mutex\)\).*"]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False
