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

class CodeLux_APIs(Signature):
    name = "codelux_behavior"
    description = "Exhibits behavior characteristic of CodeLux Keylogger"
    severity = 3
    categories = ["keylogger"]
    authors = ["KillerInstict"]
    families = ["CodeLux"]
    minimum = "1.0"

    def run(self):
        queryattribs = [
            ".*\\\\CodeluxRunPE.resources.dll$",
            ".*\\\\CodeluxRunPE.resources.exe$",
            ".*\\\\CodeluxVisionStub.resources.exe$",
            ".*\\\\CodeluxVisionStub.resources.dll$",
        ]

        for ioc in queryattribs:
            check = self.check_file(pattern=ioc, regex=True)
            if check:
                return True

        return False
