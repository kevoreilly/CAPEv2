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

class CVE_2016_0189(Signature):
    name = "cve_2016-0189"
    description = "Executes obfuscated JavaScript indicative of CVE 2016-0189 Exploit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["CVE-2016-0189"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://www.fireeye.com/blog/threat-research/2016/07/exploit_kits_quickly.html"]


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

        if "valueOf\": function" in buf and "triggerBug()" in buf and "exploit(" in buf:
            self.data.append({"cve_2016-0189_poc" : "Proof of concept exploit code used. Seen in Sundown & Neutrino exploit kits"})
            return True
