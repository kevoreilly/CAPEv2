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


class DecoyImage(Signature):
    name = "decoy_image"
    description = "Executable displays a decoy image"
    severity = 2
    categories = ["stealth"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["ShellExecuteExW"])

    def on_call(self, call, process):
        show = self.get_argument(call, "Show")
        if show:
            if int(show) == 1:
                path = self.get_argument(call, "FilePath")
                if path:
                    if path.lower().endswith((".jpg", ".jpeg", ".png", ".bmp", ".tiff")):
                        self.data.append(path)
                        if self.pid:
                            self.mark_call()

    def on_complete(self):
        if len(self.data) > 0:
            if self.results["info"]["package"] in ["exe", "bin", "msi", "dll"]:
                for dropped in self.results.get("dropped", []) or []:
                    filetype = dropped["type"]
                    if "image data," in filetype or "PC bitmap," in filetype:
                        for filepath in dropped.get("guest_paths", []) or []:
                            for decoy in self.data:
                                if filepath == decoy:
                                    return True

        return False
