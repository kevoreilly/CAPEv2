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


class StopRansomMutexes(Signature):
    name = "stop_ransom_mutexes"
    description = "Creates a known STOP ransomware variant mutex"
    severity = 3
    categories = ["ransomware"]
    families = ["STOP", "Djvu", "Keypass"]
    authors = ["bartblaze"]
    minimum = "0.5"
    evented = True
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}$",
            "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}$",
            "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}$",
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False


class StopRansomwareCMD(Signature):
    name = "stop_ransomware_cmd"
    description = "STOP ransomware command line behavior detected"
    severity = 3
    categories = ["ransomware"]
    families = ["STOP"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def run(self):
        indicators = [".*--(Admin|ForNetRes)\s.*is(Not)?(AutoStart|Task).*"]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False


class StopRansomwareRegistry(Signature):
    name = "stop_ransomware_registry"
    description = "STOP ransomware registry artifacts detected"
    severity = 3
    categories = ["ransomware"]
    families = ["STOP"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    def on_call(self, call, process):
        valuename = self.get_argument(call, "ValueName")
        if valuename == "SysHelper":
            buff = self.get_argument(call, "Buffer")
            if "--AutoStart" in buff:
                self.match = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.match:
            return True

        return False
