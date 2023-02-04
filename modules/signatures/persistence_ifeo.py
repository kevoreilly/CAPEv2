# Copyright (C) 2020 ditekshen
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


class PersistenceIFEO(Signature):
    name = "persistence_ifeo"
    description = "Modifies Image File Execution Options, indicative of process injection or persistence"
    severity = 3
    categories = ["persistence", "injection", "evasion"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1183"]  # MITRE v6
    ttps += ["T1055", "T1112"]  # MITRE v6,7,8
    ttps += ["T1546", "T1546.012"]  # MITRE v7,8
    ttps += ["U1222"]  # Unprotect
    mbcs = ["OB0012", "E1055", "E1055.m02", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Image\sFile\sExecution\sOptions\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False


class PersistenceSilentProcessExit(Signature):
    name = "persistence_slient_process_exit"
    description = "Modifies Slient Process Exit Options, indicative of process injection or persistence"
    severity = 3
    categories = ["persistence", "injection", "evasion"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1183"]  # MITRE v6
    ttps = ["T1055", "T1112"]  # MITRE v6,7,8
    ttps += ["T1546", "T1546.012"]  # MITRE v7,8
    mbcs = ["OB0012", "E1055", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\SilentProcessExit\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
