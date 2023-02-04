# CAPE - Config And Payload Extraction
# Copyright(C) 2018 redsand (redsand@redsand.net)
#
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

PROCESS_DEBUG_PORT = 0x7


# https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
class antidebug_checkremotedebuggerpresent(Signature):
    name = "antidebug_checkremotedebuggerpresent"
    description = "CheckRemoteDebuggerPresent detected (possible anti-debug)"
    severity = 3
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True
    ttps = ["T1106"]  # MITRE v6,7,8
    mbcs = ["OB0001", "B0001"]

    filter_apinames = set(["CheckRemoteDebuggerPresent", "NtQueryInformationProcess"])

    def on_call(self, call, process):
        if call["api"] == "CheckRemoteDebuggerPresent":
            self.ttps += ["U0121"]  # Unprotect
            self.mbcs += ["B0001.002"]
            if self.pid:
                self.mark_call()
            return True
        elif call["api"] == "NtQueryInformationProcess":
            ProcessInformationClass = int(self.get_raw_argument(call, "ProcessInformationClass"))
            if ProcessInformationClass == PROCESS_DEBUG_PORT:
                # other examples to monitor are:
                # - ProcessDebugObjectHandle 0x1E
                # - ProcessDebugFlags 0x1F
                # - ProcessBasicInformation 0x00
                self.ttps += ["U0120"]  # Unprotect
                self.mbcs += ["B0001.012"]
                if self.pid:
                    self.mark_call()
                return True
