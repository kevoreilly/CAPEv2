# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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


class VPCDetectKeys(Signature):
    name = "antivm_vpc_keys"
    description = "Detects Virtual PC through the presence of a registry key"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1012", "T1057", "T1497"]  # MITRE v6,7,8
    ttps += ["U1332"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.005", "OB0007"]
    mbcs += ["OC0008", "C0036", "C0036.005"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\PCI\\\\VEN_5333&DEV_8811&SUBSYS_00000000&REV_00$",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\vpc-s3$",
        ]
        for indicator in indicators:
            if self.check_key(pattern=indicator, regex=True):
                return True

        return False
