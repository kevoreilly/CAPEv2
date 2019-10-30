# Copyright (C) 2016 KillerInstinct
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

class H1N1_APIs(Signature):
    name = "h1n1_behavior"
    description = "Exhibits behavior characteristic of H1N1 downloader"
    weight = 3
    severity = 3
    categories = ["dropper"]
    families = ["H1N1"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sections = set()
        self.events = set()
        self.injPid = int()
        self.c2Pid = int()
        self.lastConnect = str()
        self.c2s = list()
        self.ret = False

    filter_apinames = set(["NtCreateSection", "NtOpenSection", "NtCreateEvent",
                           "InternetConnectA", "HttpOpenRequestA"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateSection":
            if call["status"]:
                section = self.get_argument(call, "ObjectAttributes")
                if section and len(section) > 1 and section not in self.sections:
                    self.sections.add(section[:-1])

        elif call["api"] == "NtCreateEvent":
            if call["status"]:
                event = self.get_argument(call, "EventName")
                if event and event in self.sections:
                    self.events.add(event)
                    self.injPid = process["process_id"]

        elif call["api"] == "NtOpenSection":
            if call["status"] and self.events:
                section = self.get_argument(call, "ObjectAttributes")
                if section and len(section) > 1:
                    if section[:-1] in self.events:
                        if process["process_id"] != self.injPid:
                            self.c2Pid = process["process_id"]
                            self.ret = True

        elif call["api"] == "InternetConnectA":
            if process["process_id"] == self.c2Pid:
                domain = self.get_argument(call, "ServerName")
                if domain:
                    self.lastConnect = domain

        elif call["api"] == "HttpOpenRequestA":
            if process["process_id"] == self.c2Pid:
                uri = self.get_argument(call, "Path")
                if uri:
                    if not uri.startswith("/"):
                        uri = "/" + uri
                    c2 = self.lastConnect + uri
                    if c2 not in self.c2s:
                        self.c2s.append(c2)

    def on_complete(self):
        if self.ret:
            for c2 in self.c2s:
                self.data.append({"C2": c2})

        return self.ret
