# Copyright (C) 2020 bartblaze
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


class AccessesSysvol(Signature):
    name = "accesses_sysvol"
    description = "Accesses or reads files from the SYSVOL folder, possibly to dump passwords"
    severity = 3
    categories = ["credential_access"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1081"]  # MITRE v6
    ttps += ["T1552", "T1552.001", "T1552.006"]  # MITRE v7,8
    mbcs = ["OB0005"]
    mbcs += ["OC0001", "C0051"]  # micro-behaviour

    def run(self):
        indicators = [".*\\\\Windows\\\\SYSVOL\\\\.*", "\\\\sysvol\\\\.*\\\\policies\\\\.*", "\\\\sysvol\\\\.*\\\\scripts\\\\.*"]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False


class WritesSysvol(Signature):
    name = "writes_sysvol"
    description = "Writes files to the SYSVOL folder, possibly to spread laterally"
    severity = 3
    categories = ["credential_access"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1552"]
    mbcs = ["OC0001", "C0052"]  # micro-behaviour

    def run(self):
        indicators = [".*\\\\Windows\\\\SYSVOL\\\\.*", "\\\\sysvol\\\\.*\\\\policies\\\\.*", "\\\\sysvol\\\\.*\\\\scripts\\\\.*"]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
