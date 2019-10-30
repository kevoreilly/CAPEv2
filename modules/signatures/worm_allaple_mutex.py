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

class AllapleMutexes(Signature):
    name = "allaple_mutexes"
    description = "Creates known Allaple worm mutexes"
    severity = 3
    categories = ["worm"]
    families = ["Allaple"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "^a15xv9x7s$",
            "jhdheddfffffhjk5trh",
            "jhdheruhfrthkgjhtjkghjk5trh",
            "jhdgcjhasgdc09890gjasgcjhg2763876uyg3fhg",
        ]

        for indicator in indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.data.append({"mutex": match_mutex})
                return True

        return False
