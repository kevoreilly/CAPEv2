# Copyright (C) 2017 Kevin Ross
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

class Sundown_JS(Signature):
    name = "sundown_js"
    description = "Executes obfuscated JavaScript indicative of Sundown/Nebula Exploit Kit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["Sundown"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

        self.payloadRC4keys = [
            ("key=\\\"gexywoaxor\\\"", "Uses the key gexywoaxor associated with the Sundown exploit kit"),
            ("key=\\\"galiut\\\"", "Uses the key galiut associated with the Nebula exploit kit"),
        ]

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript").lower()
        else:
            buf = self.get_argument(call, "Script").lower()

        if "ie=emulateie" in buf and "vbscript" in buf and "key=\\\"" in buf and "url=\\\"http" in buf:
            for key in self.payloadRC4keys:
                if key[0] in buf:
                    self.data.append({"Known RC4 Payload Key" : "%s" % (key[1])})
            return True
