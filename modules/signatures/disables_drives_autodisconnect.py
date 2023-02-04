# Copyright (C) 2022 ditekshen
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


class DisablesMappedDrivesAutodisconnect(Signature):
    name = "disables_mappeddrives_autodisconnect"
    description = "Attempts to disable or change the mapped dirves autodisconnect feature via command line"
    severity = 3
    categories = ["ransomware"]
    authors = ["ditekshen", "Zane C. Bowers-Hadley"]
    minimum = "1.3"
    evented = True
    ttps = ["T1059"]  # MITRE v6,7,8
    mbcs = ["OB0009", "E1059"]

    filter_apinames = set(["CreateProcessInternalW", "ShellExecuteExW", "NtCreateUserProcess"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if "config server" in cmdline and "/autodisconnect:" in cmdline and "net" in cmdline:
                if self.pid:
                    self.mark_call()
                return True
        if call["api"] == "NtCreateUserProcess":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if "config server" in cmdline and "/autodisconnect:" in cmdline and "net" in cmdline:
                if self.pid:
                    self.mark_call()
                return True
        elif call["api"] == "ShellExecuteExW":
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            if "config server" in params and "/autodisconnect:" in params and "net" in filepath:
                if self.pid:
                    self.mark_call()
                return True
