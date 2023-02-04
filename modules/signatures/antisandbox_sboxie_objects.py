# Copyright (C) 2015 KillerInstinct
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


class AntiSandboxSboxieObjects(Signature):
    name = "antisandbox_sboxie_objects"
    description = "The sample enumerated a known Sandboxie device object."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["KillerInstinct"]
    minimum = "1.0"
    evented = True
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1497", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U0513"]  # Unprotect
    mbcs = ["OB0001", "B0007", "B0009"]

    filter_apinames = set(["NtOpenDirectoryObject"])

    def on_call(self, call, process):
        objectattr = self.get_argument(call, "ObjectAttributes")
        if len(objectattr) >= 10:
            if objectattr[2:10] == r"\Sandbox":
                if self.pid:
                    self.mark_call()
                return True
