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


class LodaRATFileBehavior(Signature):
    name = "lodarat_file_behavior"
    description = "LodaRAT file modification behavior detected"
    severity = 3
    categories = ["rat"]
    families = ["LodaRAT"]
    authors = ["ditekshen"]
    minimum = "2.0"
    evented = True
    mbcs = ["OC0001"]  # micro-behaviour

    def run(self):
        file_indicators = [
            ".*\\\\AppData\\\\Roaming\\\\Windata\\\\([A-Za-z]{6}|svchost)\.exe$",
        ]

        for indicator in file_indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
