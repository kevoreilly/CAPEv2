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


class antidebug_gettickcount(Signature):
    name = "antidebug_gettickcount"
    description = "GetTickCount detected (possible anti-debug)"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True
    ttps = ["T1497"]  # MITRE v6
    ttps += ["T1497.003"]  # MITRE v7,8
    ttps += ["U0125"]  # Unprotect
    mbcs = ["OB0001", "B0001", "B0001.032"]

    filter_apinames = set(["GetTickCount"])

    def on_call(self, call, process):
        if call["api"] == "GetTickCount":
            if self.pid:
                self.mark_call()
            return True
