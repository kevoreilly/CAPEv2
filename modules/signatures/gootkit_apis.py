# Copyright (C) 2016 KillerInstinct
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

class Gootkit_APIs(Signature):
    name = "gootkit_behavior"
    description = "Exhibits behavior characteristic of Gootkit malware"
    weight = 3
    severity = 3
    categories = ["trojan"]
    families = ["gootkit"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["RegSetValueExW"])

    def on_call(self, call, process):
        bufLen = self.get_argument(call, "BufferLength")
        if bufLen and int(bufLen) > 128000:
            valName = self.get_argument(call, "ValueName")
            if valName and valName.lower().startswith("binaryimage"):
                if "_" in valName and valName[-1].isdigit():
                    return True
