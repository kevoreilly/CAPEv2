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

class Troldesh_APIs(Signature):
    name = "troldesh_behavior"
    description = "Exhibits behavior characteristic of Troldesh ransomware"
    severity = 3
    categories = ["ransomware"]
    authors = ["KillerInstinct"]
    families = ["Troldesh"]
    minimum = "1.0"

    def run(self):
        keypat = r".*\\SOFTWARE\\System32\\Configuration\\i$"
        if self.check_write_key(pattern=keypat, regex=True):
            return True

        return False
