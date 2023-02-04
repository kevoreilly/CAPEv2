# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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


class HookMouse(Signature):
    name = "antisandbox_mouse_hook"
    description = "Installs an hook procedure to monitor for mouse events"
    severity = 3
    categories = ["anti-sandbox", "generic"]
    authors = ["nex"]
    minimum = "1.0"
    evented = True
    ttps = ["T1056", "T1497"]  # MITRE v6,7,8
    ttps += ["T1497.002"]  # MITRE v7,8
    ttps += ["U1317"]  # Unprotect
    mbcs = ["OB0001", "B0007", "B0007.003", "B0009", "B0009.012", "F0003", "F0003.003", "OB0003", "E1056", "E1056.m01"]

    filter_apinames = set(["SetWindowsHookExA", "SetWindowsHookExW"])

    def on_call(self, call, process):
        if int(self.get_argument(call, "HookIdentifier")) in [7, 14]:
            if int(self.get_argument(call, "ThreadId")) == 0:
                if self.pid:
                    self.mark_call()
                return True
