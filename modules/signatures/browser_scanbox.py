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


class BrowserScanbox(Signature):
    name = "browser_scanbox"
    description = "Scanbox Activity in Browser"
    weight = 3
    severity = 3
    categories = ["exploit"]
    authors = ["Will Metcalf"]
    minimum = "1.3"
    evented = True
    ttps = ["T1056", "T1082", "T1119"]  # MITRE v6,7,8
    ttps += ["T1056.001"]  # MITRE v7,8
    ttps += ["T1592", "T1592.002", "T1592.004"]  # MITRE v8
    mbcs = ["OB0003", "OB0007", "E1056", "E1082", "F0002"]

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")
            if "softwarelist.push(" in buf.lower() and 'indexof("-2147023083")' in buf.lower():
                if self.pid:
                    self.mark_call()
                return True
            elif (
                "var logger" in buf.lower()
                and "document.onkeypress = keypress;" in buf.lower()
                and "setinterval(sendchar," in buf.lower()
            ):
                if self.pid:
                    self.mark_call()
                return True
