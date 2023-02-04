# Copyright (C) 2021 ditekshen
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


class NetworkFakeUserAgent(Signature):
    name = "network_fake_useragent"
    description = "Fake User-Agent detected"
    severity = 3
    categories = ["network", "evasion"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1032"]

    filter_apinames = set(["InternetOpenA", "WinHttpOpen"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.fakeuas = [
            "(iPhone;",
            "(iPad;",
            "(Android;",
            "like Mac OS X",
            "(Macintosh;",
            "(X11; Linux",
            "Windows NT 5.0;",
            "IEMobile",
            "Windows Phone OS",
            "(BlackBerry;",
            "by NZXER",
        ]

    def on_call(self, call, process):
        if call["api"] == "InternetOpenA":
            useragent = self.get_argument(call, "Agent")
            if useragent:
                for fakeua in self.fakeuas:
                    if fakeua in useragent:
                        self.match = True
                        self.data.append({"fake_useragent": useragent})
                        if self.pid:
                            self.mark_call()
        elif call["api"] == "WinHttpOpen":
            useragent = self.get_argument(call, "UserAgent")
            if useragent:
                for fakeua in self.fakeuas:
                    if fakeua in useragent:
                        self.match = True
                        self.data.append({"fake_useragent": useragent})
                        if self.pid:
                            self.mark_call()

    def on_complete(self):
        return self.match
