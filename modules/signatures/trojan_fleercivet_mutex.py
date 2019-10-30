# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class FleerCivetMutexes(Signature):
    name = "fleercivet_mutex"
    description = "Creates known FleerCivet mutexes"
    severity = 3
    weight = 5
    categories = ["trojan"]
    families = ["fleercivet"]
    authors = ["Optiv"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "_HSJ909NJJNJ90203_"
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator):
                return True

        return False
