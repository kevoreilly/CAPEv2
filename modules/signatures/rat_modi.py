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


class ModiRATBehavior(Signature):
    name = "modirat_behavior"
    description = "Exhibits behavioral characteristics of MoDiRAT"
    severity = 3
    categories = ["rat"]
    families = ["MoDiRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        reg_indicators = [
            "HKEY_CURRENT_USER\\\\Software\\\\FFMPEG_URL.*",
            "HKEY_CURRENT_USER\\\\Software\\\\Telegram_Notifier.*",
        ]
        file_indicators = [
            "[A-Z]:\\\\ProgramData\\\\ffmpeg\.exe$",
            "[A-Z]:\\\\.*\\\\AppData\\\\Roaming\\\\WindowsCodecs\.dll$",
            "[A-Z]:\\\\.*\\\\AppData\\\\Roaming\\\\Lanceur\.vbs$",
            "[A-Z]:\\\\.*\\\\AppData\\\\Roaming\\\\LeFichier\.txt$",
            "[A-Z]:\\\\.*\\\\AppData\\\\Roaming\\\\txt\.txt$",
            "[A-Z]:\\\\.*\\\\AppData\\\\Roaming\\\\MSBuild\.exe$",
        ]
        score = int()

        for rindicator in reg_indicators:
            match = self.check_write_key(pattern=rindicator, regex=True, all=True)
            if match:
                score += 1

        for findicator in file_indicators:
            match = self.check_write_file(pattern=findicator, regex=True, all=True)
            if match:
                score += 1

        if score >= 4:
            return True

        return False
