# Copyright (C) 2016 Brad Spengler
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

class ThreatTrackDetectFiles(Signature):
    name = "antisandbox_threattrack_files"
    description = "Attempts to detect ThreatTrack/GFI/CW Sandbox through the presence of a file"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Brad Spengler"]
    minimum = "0.5"
    ttp = ["T1083", "T1057"]

    def run(self):
        indicators = [
            "^C:\\\\cwsandbox",
            "^C:\\\\gfisandbox",
            "^C:\\\\sandbox\\\\starter\.exe$",
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True

        return False
