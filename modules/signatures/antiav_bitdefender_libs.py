# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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


class BitdefenderDetectLibs(Signature):
    name = "antiav_bitdefender_libs"
    description = "Detects Bitdefender Antivirus through the presence of a library"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1083", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0001", "OB0007"]

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def on_call(self, call, process):
        dllname = self.get_argument(call, "FileName")
        if "avcuf32" in dllname.lower():
            if self.pid:
                self.mark_call()
            return True
