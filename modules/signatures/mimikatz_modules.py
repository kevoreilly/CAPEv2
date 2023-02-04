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


class MimikatzModules(Signature):
    name = "mimikatz_modules"
    description = "Executed a potential Mimikatz module"
    severity = 3
    categories = ["lateral", "credential_dumping"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["S0002"]  # MITRE
    ttps += ["T1003"]  # MITRE v6,7,8

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if (
                "CRYPTO::" in lower
                or "KERBEROS::" in lower
                or "LSADUMP::" in lower
                or "MISC::" in lower
                or "PRIVILEGE::" in lower
                or "SEKURLSA::" in lower
                or "TOKEN::" in lower
            ):
                ret = True
                self.data.append({"module": cmdline})

        return ret
