# Copyright (C) 2021 bartblaze
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


class AntiEmuWinDefend(Signature):
    name = "antiemu_windefend"
    description = "Detects the presence of Windows Defender AV emulator via files"
    severity = 3
    categories = ["anti-emulation"]
    authors = ["bartblaze"]
    minimum = "0.5"
    ttps = ["T1057", "T1083", "T1497", "T1518"]  # MITRE v6,7,8
    mbcs = ["OB0001", "B0004"]
    references = [
        "https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf"
    ]

    def run(self):
        indicators = [
            "C:\\\\aaa_TouchMeNot_.txt$",
            "C:\\\\Mirc\\\\mirc.ini$",
            "C:\\\\Mirc\\\\script.ini$",
            "C:\\\\Windows\\\\msdfmap.ini$",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
