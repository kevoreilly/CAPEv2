# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
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

class VMwareDetectKeys(Signature):
    name = "antivm_vmware_keys"
    description = "Detects VMware through the presence of a registry key"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1057", "T1012"]

    def run(self):
        indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?VMWare,\\ Inc\..*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Clients\\\\StartMenuInternet\\\\VMWAREHOSTOPEN.EXE$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?\\\\Microsoft\\\\ESENT\\\\Process\\\\vmtoolsd$",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\CriticalDeviceDatabase\\\\root#vmwvmcihostdev$",
        ]

        for indicator in indicators:
            if self.check_key(pattern=indicator, regex=True):
                return True

        return False
