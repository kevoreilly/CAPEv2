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

class Angler_JS(Signature):
    name = "angler_js"
    description = "Executes obfuscated JavaScript indicative of Angler Exploit Kit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["angler"]
    authors = ["Optiv"]
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

        if "/malware.dontneedcoffee.com/.test()" in buf:
            return True
        if "Kaspersky.IeVir' + " in buf:
            return True
        if "+'%u0000')" in buf and "Math.floor(Math.random() * (6 -3) +3);" in buf and "{return 'Accept: ' +'*' +'/' +'*' +'" in buf:
            return True
        if "2830293d2668364336343734364526" in buf.lower() and "2831293d2668364336343245364326" in buf.lower() and "2832293d2668373236393536373426" in buf.lower():
            return True
        if "value='\" +url" in buf.lower() and "<param name='play' value='true'>\" + \"<param name='flashvars'" in buf.lower():
            return True
        if "getkolaio()" in buf.lower():
            return True
        if "var cryptKey = " in buf.lower():
            return True
