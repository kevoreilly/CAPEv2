# Copyright (C) 2020 bartblaze
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

class SatanMutexes(Signature):
    name = "satan_mutexes"
    description = "Creates a known Satan ransomware variant mutex"
    severity = 3
    categories = ["ransomware"]
    families = ["Satan", "DBGer", "Lucky", "5ss5c"]
    authors = ["bartblaze"]
    minimum = "0.5"

    def run(self):
        indicators = [
			"SATANAPP",
			"SATAN_SCAN_APP",
			"STA__APP",
			"DBGERAPP",
			"DBG_CPP",
			"lucky$",
			"run_STT",
			"SSS_Scan",
			"SSSS_Scan",
			"5ss5c_CRYPT"
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False
