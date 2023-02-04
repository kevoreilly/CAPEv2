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


class PowerpoolMutexes(Signature):
    name = "powerpool_mutexes"
    description = "Creates known PowerPool mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["PowerPool"]
    authors = ["ditekshen"]
    minimum = "0.5"
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "MyDemonMutex\d+$",
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False
