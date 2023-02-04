# Copyright (C) 2016 Kevin Ross
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


class NetworkAdapters(Signature):
    name = "antivm_network_adapters"
    description = "Checks adapter addresses which can be used to detect virtual network interfaces"
    severity = 1
    confidence = 40
    categories = ["anti-vm"]
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    evented = True

    filter_apinames = set(["GetAdaptersAddresses"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.safelistprocs = [
            "iexplore.exe",
            "firefox.exe",
            "chrome.exe",
            "safari.exe",
            "outlook.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
        ]

    def on_call(self, _, process):
        if process["process_name"].lower() not in self.safelistprocs:
            if self.pid:
                self.mark_call()
            return True
