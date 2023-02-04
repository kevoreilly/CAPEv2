# Copyright (C) 2019 Kevin Ross
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


class sysinternals_tools(Signature):
    name = "sysinternals_tools"
    description = "Executed a sysinternals tool"
    severity = 2
    categories = ["command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    mbcs = ["OB0009", "E1203", "E1203.m05"]
    references = ["https://docs.microsoft.com/en-us/sysinternals/"]

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Sysinternals\\\\.*",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True

        return False


class sysinternals_psexec(Signature):
    name = "sysinternals_psexec"
    description = "PSExec was executed"
    severity = 3
    categories = ["command", "lateral"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1203"]  # MITRE v6,7,8
    mbcs = ["OB0009", "E1203", "E1203.m05"]
    references = ["https://docs.microsoft.com/en-us/sysinternals/"]

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Sysinternals\\\\PsExec\\\\.*",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True

        return False
