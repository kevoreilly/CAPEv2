# Copyright (C) 2023 Kevin Ross
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


class DisablesCrashdumps(Signature):
    name = "disables_crashdumps"
    description = "Attempts to disable crashdumps"
    severity = 2
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    ttps = ["T1070"]

    def run(self):
        ret = False

        keys = [
            ".*\\\\SYSTEM\\\\(Wow6432Node\\\\)?ControlSet001\\\\Control\\\\CrashControl\\\\CrashDumpEnabled$",
        ]

        for check in keys:
            match = self.check_write_key(pattern=check, regex=True)
            if match:
                self.data.append({"regkey": match})
                ret = True

        return ret
