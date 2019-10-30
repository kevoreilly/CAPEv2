# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com 
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

class CVE_2014_6332(Signature):
    name = "cve_2014_6332"
    description = "Executes obfuscated JavaScript Indicative of CVE 2014-6332 Exploit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["CVE-2014-6332"]
    authors = ["Will Metcalf"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        if "chrw(01)&chrw(2176)&chrw(01)&chrw(00)" in buf and "chrw(00)&chrw(32767)&chrw(00)&chrw(0)" in buf:
            return True
        if "function setnotsafemode" in buf and "function runmumaa" in buf:
            return True

