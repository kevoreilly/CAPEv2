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

class Webmail_Phish(Signature):
    name = "webmail_phish"
    description = "Network activity contains known webmail credential phishing indicators."
    severity = 3
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Lower case for now, may tighten later
        self.indicators = [
           "validateformyahoo()",
           "validateformhotmail()",
           "validateformgmail()",
           "validateformaol()",
           "validateformother()",
        ]
        self.hits = set()

    # Observed with IE8
    filter_apinames = set(["InternetReadFile"])

    def on_call(self, call, process):
        data = self.get_argument(call, "Buffer")
        if data:
            for indicator in self.indicators:
                if indicator in data.lower():
                    self.hits.add(indicator)

    def on_complete(self):
        ret = False
        if self.hits:
            ret = True
            for item in self.hits:
                self.weight += 1

        return ret
