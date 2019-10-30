# Copyright (C) 2012,2015 Thomas "stacks" Birn (@stacksth), Optiv, Inc. (brad.spengler@optiv.com)
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

class DisableRegedit(Signature):
    name = "locker_regedit"
    description = "Disables Windows' Registry Editor"
    severity = 3
    categories = ["locker"]
    authors = ["Thomas Birn", "nex", "Optiv"]
    minimum = "1.2"
    ttp = ["T1112"]

    def run(self):
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\DisableRegistryTools$", regex=True):
            return True

        return False