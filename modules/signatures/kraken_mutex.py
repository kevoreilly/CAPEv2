# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com 
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

class KrakenMutexes(Signature):
    name = "bot_kraken_mutexes"
    description = "Creates known Kraken mutexes"
    severity = 3
    categories = ["bot"]
    families = ["kraken"]
    authors = ["wmetcalf"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "yourhavebecracked",
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=False):
                return True

        return False
