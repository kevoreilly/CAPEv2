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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Kovter_APIs(Signature):
    name = "kovter_behavior"
    description = "Exhibits behavior characteristic of Kovter malware"
    severity = 3
    weight = 3
    categories = ["clickfraud", "downloader"]
    families = ["kovter"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastapi = str()
        self.chain = False

    filter_apinames = set(["CreateThread", "NtCreateEvent", "NtCreateSection",
                           "LdrGetProcedureAddress"])

    def on_call(self, call, process):
        continueChain = False
        if call["status"]:
            if call["api"] == "LdrGetProcedureAddress":
                resolved = self.get_argument(call, "FunctionName")
                if resolved and resolved == "IsWow64Process":
                    continueChain = True

            elif call["api"] == "NtCreateEvent":
                if self.lastapi == "LdrGetProcedureAddress" and self.chain:
                    event = self.get_argument(call, "EventName")
                    if event and re.match("^[0-9A-F]{32}$", event):
                        continueChain = True

            elif call["api"] == "NtCreateSection":
                if self.lastapi == "NtCreateEvent" and self.chain:
                    attribs = self.get_argument(call, "ObjectAttributes")
                    if attribs and re.match("^[0-9A-F]{32}$", attribs):
                        continueChain = True

            elif call["api"] == "CreateThread":
                if self.lastapi == "NtCreateSection" and self.chain:
                    return True

        self.chain = continueChain
        self.lastapi = call["api"]
