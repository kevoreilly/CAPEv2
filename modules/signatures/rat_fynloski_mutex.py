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


class FynloskiMutexes(Signature):
    name = "rat_fynloski_mutexes"
    description = "Creates known Fynloski/DarkComet mutexes"
    severity = 3
    categories = ["rat"]
    families = ["Darkcomet", "Fynloski"]
    authors = ["threatlead"]
    references = ["https://malwr.com/analysis/ODVlOWEyNDU3NzBhNDE3OWJkZjE0ZjIxNTdiMzU1YmM/"]
    minimum = "0.5"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = ["DC_MUTEX-.*"]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False
