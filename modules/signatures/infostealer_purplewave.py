# Copyright (C) 2020 ditekshen
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


class PurpleWaveMutexes(Signature):
    name = "purplewave_mutexes"
    description = "PurpleWave infostealer mutexes detected"
    severity = 3
    categories = ["infostealer"]
    families = ["PurpleWave"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    mbcs = ["OC0003", "C0043"]  # micro-behaviour

    def run(self):
        indicators = [
            "^MutexCantRepeatThis$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False


class PurpleWaveNetworkAcivity(Signature):
    name = "purplewave_network_activity"
    description = "PurpleWave infostealer network activity detected"
    severity = 3
    categories = ["infostealer"]
    families = ["PurpleWave"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.001"]  # MITRE v7,8
    mbcs = ["OC0006", "C0002"]  # micro-behaviour

    filter_apinames = set(["InternetOpenW", "HttpAddRequestHeadersA", "HttpSendRequestW", "HttpOpenRequestW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.uamatch = False
        self.urmatch = False
        self.hematch = False
        self.pomatch = False

    def on_call(self, call, process):
        if call["api"] == "InternetOpenW":
            useragent = self.get_argument(call, "Agent")
            if useragent and useragent == "app":
                if self.pid:
                    self.mark_call()
                self.uamatch = True

        if call["api"] == "HttpAddRequestHeadersA":
            headers = self.get_argument(call, "Headers")
            if headers and "boundary=boundaryaswell" in headers:
                if self.pid:
                    self.mark_call()
                self.hematch = True

        if call["api"] == "HttpSendRequestW":
            postdata = self.get_argument(call, "PostData")
            if postdata and "--boundaryaswell" in postdata:
                if self.pid:
                    self.mark_call()
                self.pomatch = True

        if call["api"] == "HttpOpenRequestW":
            httppath = self.get_argument(call, "Path")
            httpverb = self.get_argument(call, "Verb")
            if httppath and httpverb:
                if (httppath == "/config" or httppath == "/gate") and httpverb == "POST":
                    if self.pid:
                        self.mark_call()
                    self.urmatch = True

    def on_complete(self):
        if self.uamatch and (self.hematch or self.pomatch) and self.urmatch:
            return True

        return False
