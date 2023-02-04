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


class PoullightFiles(Signature):
    name = "poullight_files"
    description = "Poullight infostealer file artifacts detected"
    severity = 3
    categories = ["infostealer"]
    families = ["Poullight"]
    authors = ["ditekshen"]
    minimum = "2.0"
    evented = True
    ttps = ["T1003", "T1113", "T1115"]  # MITRE v6,7,8
    mbcs = ["OB0003", "OB0005", "E1113"]
    mbcs += ["OC0001", "C0052"]  # micro-behaviour

    def run(self):
        score = 0
        fpath = ".*\\\\AppData\\\\Local\\\\[a-z0-9]{8}\\\\"
        flist = [
            "system\.txt",
            "processlist\.txt",
            "copyboard\.txt",
            "screenshot\.png",
            "Grabber\\\\.*",
            "FileZilla\\\\data\.txt",
            "Pidgin\\\\data\.txt",
            "Discord\\\\data\.txt",
            "Telegram\\\\data\.txt",
            "Steam\\\\data\.txt",
            "webcam\.jpg",
            "accountlogin\.txt",
        ]

        for lfile in flist:
            indicator = fpath + lfile
            # modified + deleted
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score > 6:
            return True

        return False
