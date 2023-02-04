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


class CVE_2016_7200(Signature):
    name = "cve_2016_7200"
    description = "Executes obfuscated JavaScript Indicative of CVE 2016-7200 Microsoft Edge Exploit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["CVE-2016_7200"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1203", "T1499"]  # MITRE v6,7,8
    ttps += ["T1499.004"]  # MITRE v7,8
    mbcs = ["OB0008", "B0033", "E1203", "OB0009"]
    references = ["http://malware.dontneedcoffee.com/2017/01/CVE-2016-7200-7201.html"]

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        if " getPrototypeOf" in buf and "__proto__" in buf and "Array" in buf and "Symbol" in buf:
            if self.pid:
                self.mark_call()
            return True
