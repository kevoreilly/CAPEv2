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

class SunbeltDetectLibs(Signature):
    name = "antisandbox_sunbelt_libs"
    description = "Detects SunBelt Sandbox through the presence of a library"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttp = ["T1083", "T1057"]
    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def on_call(self, call, process):
        indicators = [
                "api_log",
                "dir_watch"
            ]
        dllname = self.get_argument(call, "FileName").lower()
        
        for indicator in indicators:
            if indicator in dllname:
                return True
