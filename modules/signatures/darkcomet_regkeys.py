# Copyright (C) 2015 KillerInstinct
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

class DarkCometRegkeys(Signature):
    name = "darkcomet_regkeys"
    description = "Interacts with known DarkComet registry keys"
    severity = 3
    categories = ["rat"]
    families = ["darkcomet"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        dc_keys = False
        indicators = [
                ".*\\\\Software\\\\DC3_FEXEC$",
                ".*\\\\Software\\\\DC3_FEXEC\\\\.*",
                ".*\\\\Software\\\\DC2_USERS$",
            ]
        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"Key": match})
                dc_keys = True

        return dc_keys
