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


class ExplorerHTTP(Signature):
    name = "explorer_http"
    description = "Explorer.exe process established HTTP connections"
    severity = 4
    categories = ["masquerading", "evasion", "execution", "injection"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1036", "T1055", "T1071"]  # MITRE v6,7,8
    ttps += ["T1071.001"]  # MITRE v7,8
    mbcs = ["E1055"]
    mbcs += ["OC0006", "C0002"]  # micro-behaviour

    filter_apinames = set(["WinHttpConnect", "WinHttpOpenRequest"])

    def on_call(self, call, process):
        processname = process["process_name"].lower()
        if processname == "explorer.exe":
            if call["api"] == "WinHttpConnect":
                servername = self.get_argument(call, "ServerName")
                serverport = self.get_argument(call, "ServerPort")
                if servername and serverport:
                    self.data.append({"Domain:Port": servername + ":" + serverport})
                    if self.pid:
                        self.mark_call()
            if call["api"] == "WinHttpOpenRequest":
                httpverb = self.get_argument(call, "Verb")
                httpuri = self.get_argument(call, "ObjectName")
                if httpverb and httpuri:
                    self.data.append({"HTTPMethod:URI": httpverb + ":" + httpuri})
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        if len(self.data) > 0:
            return True
