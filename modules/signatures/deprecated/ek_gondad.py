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


class Gondad_JS(Signature):
    name = "gondad_js"
    description = "Executes obfuscated JavaScript indicative of Gondad Exploit Kit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["Gondad"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True
    ttps = ["T1064"]  # MITRE v6
    ttps += ["T1059", "T1190", "T1203"]  # MITRE v6,7,8
    ttps += ["T1059.007"]  # MITRE v7,8
    mbcs = ["OB0008", "E1059", "E1203", "OB0009", "E1190"]

    filter_categories = set(["browser"])
    filter_apinames = set(["CDocument_write"])

    def on_call(self, call, process):
        buf = self.get_argument(call, "Buffer")
        if buf and buf.count("gondad") > 4:
            if self.pid:
                self.mark_call()
            return True
