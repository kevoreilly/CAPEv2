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

try:
    import re2 as re
except:
    import re

from lib.cuckoo.common.abstracts import Signature

class Generic_Phish(Signature):
    name = "generic_phish"
    description = "Network activity contains generic phishing indicators indicative of a website clone."
    severity = 2
    weight = 2
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Named group to extract the URL of the cloned website.
        self.rex = {
            "saved from url": re.compile(r"\<!--\ssaved\sfrom\surl=\(\d+\)(?P<url>[^\s]+)", re.I),
            "mirrored from": re.compile(r"<!--\smirrored\sfrom\s(?P<url>[^\s]+)\sby\sHTTrack", re.I),
        }
        self.hits = set()

    # Observed with IE8
    filter_apinames = set(["InternetReadFile"])

    def on_call(self, call, process):
        data = self.get_argument(call, "Buffer")
        if data and "<!--" in data:
            for regex in self.rex.keys():
                if regex in data.lower():
                    buf = self.rex[regex].search(data)
                    if buf:
                        if "-->" in data:
                            self.hits.add((buf.group("url"), "ok"))
                        else:
                            self.hits.add((buf.group("url"), "truncated"))

    def on_complete(self):
        ret = False
        if self.hits:
            ret = True
            for url, info in self.hits:
                self.data.append({"Page cloned from": url})
                if info == "truncated":
                    self.data.append({"Note": "The above URL may be truncated"})

        return ret
