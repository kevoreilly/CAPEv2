# Copyright (C) 2015 Kevin Ross
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

class Virtualcheck_JS(Signature):
    name = "virtualcheck_js"
    description = "Executes obfuscated JavaScript checking for analysis tools or sandbox/VM environment"
    weight = 3
    severity = 3
    categories = ["exploit_kit", "evasion"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        indicators = [
                "vmusbmouse",
                "vmhgfs",
                "vboxguest",
                "vboxmouse",
                "vmmouse",
                "vm3dmp",
                "prl_boot",
                "prl_fs",
                "prl_kmdd",
                "prl_memdev",
                "prl_mouf",
                "prl_pv32",
                "prl_sound",
                "prl_prl_strg",
                "prl_tg",
                "prl_time",
                "Kaspersky.IeVirtualKeyboardPlugin",
                "isPhantom",
                "isNodeJs",
                "isCouchJs",
                "isRhino",
                "isDebugger"
                "IE_DEVTOOLBAR_CONSOLE_COMMAND_LINE"
                "BROWSERTOOLS_CONSOLE_SAFEFUNC"
            ]

        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        # As second test we bring everything together to remove split string obfuscation and see if we have any in remaining buffer too
        buf2 = buf.translate(None, " \"+'")

        for indicator in indicators:
            if indicator.lower() in buf.lower() or indicator.lower() in buf2.lower():
                return True
