# Copyright (C) 2014-2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class SandboxieDetectLibs(Signature):
    name = "antisandbox_sboxie_libs"
    description = "Detects Sandboxie through the presence of a library"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttp = ["T1063"]

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def on_call(self, call, process):
        dllname = self.get_argument(call, "FileName")
        if "sbiedll" in dllname.lower():
            return True
