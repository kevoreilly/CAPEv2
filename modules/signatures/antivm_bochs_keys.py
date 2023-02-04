# Copyright (C) 2016 Brad Spengler
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


class BochsDetectKeys(Signature):
    name = "antivm_bochs_keys"
    description = "Detects Bochs through the presence of a registry key"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Brad Spengler"]
    minimum = "0.5"
    ttps = ["T1012", "T1057"]  # MITRE v6,7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0001", "B0004", "B0004.003", "B0009", "B0009.005", "OB0007", "B0013"]
    mbcs += ["OC0008", "C0036.005"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\HARDWARE\\\\ACPI\\\\(DSDT|FADT|RSDT)\\\\BOCHS_.*",
        ]
        for indicator in indicators:
            if self.check_key(pattern=indicator, regex=True):
                return True

        return False
