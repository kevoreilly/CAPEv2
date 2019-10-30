# Copyright (C) 2012,2016 Claudio "nex" Guarnieri (@botherder), Brad Spengler
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

class VBoxDetectKeys(Signature):
    name = "antivm_vbox_keys"
    description = "Detects VirtualBox through the presence of a registry key"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex", "Brad Spengler"]
    minimum = "0.5"
    ttp = ["T1057", "T1012"]

    def run(self):
        indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Oracle\\\\VirtualBox\\ Guest\\ Additions$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Oracle\\ VM\\ VirtualBox\\ Guest\\ Additions$",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\PCI\\\\VEN_80EE&DEV_BEEF&SUBSYS_00000000&REV_00$",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\PCI\\\\VEN_80EE&DEV_CAFE&SUBSYS_00000000&REV_00$",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\VirtualDeviceDrivers$",
            ".*\\\\HARDWARE\\\\ACPI\\\\(DSDT|FADT|RSDT)\\\\VBOX__.*",
        ]
        for indicator in indicators:
            if self.check_key(pattern=indicator, regex=True):
                return True

        return False
