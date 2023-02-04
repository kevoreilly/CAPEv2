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


class DriverFilterManager(Signature):
    name = "driver_filtermanager"
    description = "Attempts to make use of the Filter Manager"
    severity = 1
    categories = ["stealth"]
    authors = ["bartblaze"]
    minimum = "0.5"
    ttps = ["T1083"]
    references = ["https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"]

    def run(self):
        indicators = [
            ".*FltMgr$",
            ".*FltMgrMsg$",
        ]

        detected = False
        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                self.data.append({"pattern": indicator})
                detected = True

        return detected
