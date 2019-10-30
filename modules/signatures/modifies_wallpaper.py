# Copyright (C) 2016 Kevin Ross, Brad Spengler
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

class ModifiesDesktopWallpaper(Signature):
    name = "modifies_desktop_wallpaper"
    description = "Attempts to modify desktop wallpaper"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross","Brad Spengler"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["SystemParametersInfoA", "SystemParametersInfoW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def on_call(self, call, process):
        action = int(self.get_argument(call, "Action"), 16)
        if action == 0x14:
            return True

    def on_complete(self):
        reg_indicators = [
            ".*\\\\Control\\ Panel\\\\Desktop\\\\Wallpaper$",
            ".*\\\\Internet\\ Explorer\\\\Desktop\\\\General\\\\Wallpaper$",
        ]
        for indicator in reg_indicators:
            if self.check_write_key(pattern=indicator, regex=True):
                return True

        return False
