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

class AntiSandboxRestart(Signature):
    name = "antisandbox_restart"
    description = "Attempts to restart the guest VM"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Brad Spengler"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["NtShutdownSystem", "NtSetSystemPowerState", "ExitWindowsEx", "InitiateShutdownW", "InitiateSystemShutdownW", "InitiateSystemShutdownExW", "NtRaiseHardError"])

    def on_call(self, call, process):
        if call["api"] == "NtRaiseHardError":
            response = int(self.get_argument(call, "ResponseOptions"))
            if response == 6:
                return True
        else:
            return True
