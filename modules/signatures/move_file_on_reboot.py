# CAPE - Config And Payload Extraction
# Copyright(C) 2018 redsand (redsand@redsand.net)
#
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

MOVEFILE_DELAY_UNTIL_REBOOT = 0x4


class move_file_on_reboot(Signature):
    name = "move_file_on_reboot"
    description = "Scheduled file move on reboot detected"
    severity = 1
    categories = ["malware"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["MoveFileWithProgressTransactedW", "MoveFileWithProgressTransactedA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    def on_call(self, call, process):
        if (
            call["api"] == "MoveFileWithProgressTransactedW"
            or call["api"] == "MoveFileWithProgressTransactedA"
            and self.get_raw_argument(call, "Flags") == MOVEFILE_DELAY_UNTIL_REBOOT
        ):
            # Filter out noise such as renaming C:\\Users\\Bubba\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_wide_alternate.db ...
            # C:\\Users\\Bubba\\AppData\\Local\\Microsoft\\Windows\\Explorer\\IconCacheToDelete\\icn30DD.tmp
            existingname = self.get_argument(call, "ExistingFileName")
            newname = self.get_argument(call, "NewFileName")
            if (
                existingname
                and newname
                and not existingname.find("\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_")
                and not newname.find("\\AppData\\Local\\Microsoft\\Windows\\Explorer\\IconCacheToDelete\\")
            ):
                self.data.append({"File Move on Reboot": "Old: %s -> New: %s" % (existingname, newname)})
                self.match = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        return self.match
