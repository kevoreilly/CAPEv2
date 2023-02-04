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

PAGE_GUARD = 0x100


class antidebug_guardpages(Signature):
    name = "antidebug_guardpages"
    description = "Guard pages use detected - possible anti-debugging."
    severity = 2
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True
    ttps = ["T1106"]  # MITRE v6,7,8
    ttps += ["U0102"]  # Unprotect
    mbcs = ["OB0001", "B0001", "B0001.009", "B0002", "B0002.008"]
    mbcs += ["OC0002", "C0008"]  # micro-behaviour

    filter_apinames = set(["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "VirtualProtectEx"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.found = False

    def on_call(self, call, _):
        if call["api"] in ["NtAllocateVirtualMemory", "VirtualProtectEx"]:
            protection = self.get_raw_argument(call, "Protection")
            if not protection:
                return False
            else:
                protection = int(protection, 0)
            if protection & PAGE_GUARD:
                self.found = True
        elif call["api"] == "NtProtectVirtualMemory":
            protection = self.get_raw_argument(call, "NewAccessProtection")
            if not protection:
                return False
            else:
                protection = int(protection, 0)
            if protection & PAGE_GUARD:
                self.found = True
        if self.found:
            if self.pid:
                self.mark_call()

    def on_complete(self):
        if self.found:
            return True
