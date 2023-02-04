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


class PersistenceRDPRegistry(Signature):
    name = "persistence_rdp_registry"
    description = "Modifies Terminal Server registry keys for persistence"
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttps = ["T1021", "T1112"]  # MITRE v6,7,8
    ttps += ["T1021.001"]  # MITRE v7,8
    mbcs = ["OB0012", "B0022", "E1203.m01", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        ret = False
        reg_indicators = [
            ".*\\\\Control\\\\Terminal Server\\\\fSingleSessionPerUser$",
            ".*\\\\Control\\\\Terminal Server\\\\fDenyTSConnections$",
            ".*\\\\Control\\\\Terminal Server\\\\fAllowToGetHelp$",
        ]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                ret = True
                self.data.append({"regkey": match})

        return ret


class PersistenceRDPShadowing(Signature):
    name = "persistence_rdp_shadowing"
    description = "Writes to the Terminal Server registry set, potentially for RDP shadowing and persistence."
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttps = ["T1021"]
    references = ["https://bitsadm.in/blog/spying-on-users-using-rdp-shadowing"]

    def run(self):
        ret = False
        reg_indicators = [
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal Services$",
        ]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                ret = True
                self.data.append({"regkey": match})

        return ret
