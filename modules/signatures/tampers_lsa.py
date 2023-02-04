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


class LSATampering(Signature):
    name = "lsa_tampering"
    description = (
        "Tampers with the Local Security Authority registry keys, potentially to allow for persistence or execution of tools."
    )
    severity = 2
    categories = ["persistence", "execution"]
    authors = ["bartblaze"]
    minimum = "1.2"
    references = [
        "https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
    ]

    def run(self):
        ret = False

        keys = [
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\.*",
        ]

        for check in keys:
            match = self.check_write_key(pattern=check, regex=True)
            if match:
                self.data.append({"regkey": match})
                ret = True

        return ret
