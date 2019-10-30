# Copyright (C) 2015 KillerInstinct
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

class JS_Phish(Signature):
    name = "js_phish"
    description = "Executes JavaScript with known {0} related phishing lures."
    weight = 2
    severity = 3
    categories = ["phishing"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lures = [
            ("debug malware error", "Malware/Infection"),
            ("contact microsoft certified", "Malware/Infection"),
            ("non bootable situation", "Malware/Infection"),
            ("windows system alert", "Malware/Infection"),
            ("your browser has been infected", "Malware/Infection"),
            ("your paypal id or password was entered incorrectly", "PayPal"),
            ("your customer number is made up of your date of birth", "NatWest"),
            ("alert(\"Invalid Card Number\")", "Banking"),
            ("alert(\"Invalid Card Verification Number\")", "Banking"),
        ]
        self.lurehits = set()
        self.totalhits = 0

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        for lure in self.lures:
            if lure[0].lower() in buf.lower():
                self.lurehits.add(lure[1])
                self.totalhits += 1

    def on_complete(self):
        if self.totalhits:
            self.weight += self.totalhits
            self.description = self.description.format("/".join(self.lurehits))
            return True

        return False
