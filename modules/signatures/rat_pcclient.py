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


class PcClientMutexes(Signature):
    name = "rat_pcclient"
    description = "Creates known PcClient mutex and/or file changes."
    severity = 3
    categories = ["rat"]
    families = ["PcClient"]
    authors = ["threatlead"]
    references = ["https://malwr.com/analysis/MDIxN2NhMjg4MTg2NDY4MWIyNTE0Zjk5MTY1OGU4YzE/"]
    minimum = "0.5"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

    def run(self):
        indicators = [
            "BKLANG.*",
            "VSLANG.*",
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                self.mbcs += ["OC0003", "C0042"]  # micro-behaviour
                return True

        indicators = [
            ".*\\\\syslog.dat",
            ".*\\\\.*_lang.ini",
            ".*\\\\[0-9]+_lang.dll",
            ".*\\\\[0-9]+_res.tmp",
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                self.mbcs += ["OC0001", "C0016"]  # micro-behaviour
                return True

        return False
