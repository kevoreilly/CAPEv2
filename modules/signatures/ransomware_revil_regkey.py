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


class RevilRegkey(Signature):
    name = "ransomware_revil_regkey"
    description = "Detects a registry key set by REvil/Sodinokibi."
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttps = ["T1486"]

    def run(self):
        ret = False
        reg_indicators = ["HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\BlackLivesMatter"]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator)
            if match:
                ret = True
                self.data.append({"regkey": match})

        return ret
