# Copyright (C) 2012,2014 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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


class AntiVMServices(Signature):
    name = "antivm_generic_services"
    description = "Enumerates services, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex", "Optiv"]
    minimum = "1.0"
    evented = True
    ttps = ["T1007", "T1012", "T1497"]  # MITRE v6,7,8
    ttps += ["T1497.001"]  # MITRE v7,8
    ttps += ["U1337"]  # Unprotect
    mbcs = ["OB0007", "B0009.005", "B0009.006", "E1082"]
    mbcs += ["OC0008", "C0036", "C0036.005", "C0036.006"]  # micro-behaviour

    # filter_apinames = set(["EnumServicesStatus", "EnumServicesStatusEx", "RegOpenKeyExA", "RegEnumKeyExA", "RegOpenKeyExW", "RegEnumKeyExW"])
    filter_apinames = set(["RegOpenKeyExA", "RegEnumKeyExA", "RegOpenKeyExW", "RegEnumKeyExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, process):
        # this API is not currently hooked
        # if call["api"].startswith("EnumServicesStatus"):
        #    return True

        if process is not self.lastprocess:
            self.handle = None
            self.lastprocess = process

        if not self.handle:
            if call["api"].startswith("RegOpenKeyEx"):
                correct = False
                if self.get_argument(call, "SubKey").lower() == "system\\controlset001\\services":
                    correct = True
                elif self.get_argument(call, "SubKey").lower() == "system\\currentcontrolset\\services":
                    correct = True

                if correct:
                    self.handle = self.get_argument(call, "Handle")
                else:
                    self.handle = None
        else:
            if call["api"].startswith("RegEnumKeyEx"):
                if self.get_argument(call, "Handle") == self.handle:
                    if self.pid:
                        self.mark_call()
                    return True
