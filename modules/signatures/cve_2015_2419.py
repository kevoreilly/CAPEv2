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

class CVE2015_2419_JS(Signature):
    name = "cve_2015_2419_js"
    description = "Executes obfuscated JavaScript containing CVE-2015-2419 Internet Explorer Jscript9 JSON.stringify double free memory corruption attempt"
    severity = 3
    categories = ["exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    references = ["https://www.fireeye.com/blog/threat-research/2015/08/cve-2015-2419_inte.html", "blog.checkpoint.com/2016/02/10/too-much-freedom-is-dangerous-understanding-ie-11-cve-2015-2419-exploitation/"]
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

        if "JSON[" in buf and "prototype" in buf and "stringify" in buf:
            return True
