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

class Vawtrak_APIs(Signature):
    name = "vawtrak_behavior"
    description = "Exhibits behavior characteristics of Vawtrak / Neverquest malware."
    severity = 3
    weight = 3
    categories = ["banking", "trojan"]
    families = ["vawtrak", "neverquest"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["NtOpenProcess", "NtCreateEvent", "NtOpenEvent",
                           "NtCreateMutant", "RegSetValueExA", "CreateThread"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.vawtrakauto = False
        self.eventtrigger = False
        self.eventcount = int()
        self.malscore = int()
        self.lastcall = str()

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            # Autorun registry / filesystem behavior
            key = self.get_argument(call, "FullName").lower()
            if "\\software\\microsoft\\windows\\currentversion\\run\\" in key:
                buf = self.get_argument(call, "Buffer").lower()
                if re.match(r"^[A-Z]:\\ProgramData\\\w+\\\w+\.exe$", buf):
                    self.vawtrakauto = True

        elif call["api"] == "NtCreateEvent" or call["api"] == "NtOpenEvent":
            buf = self.get_argument(call, "EventName")
            if re.match(r"^\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$", buf):
                self.eventtrigger = True
            else:
                self.eventtrigger = False

        elif call["api"] == "CreateThread" or call["api"] == "NtOpenProcess":
            if self.eventtrigger:
                self.malscore += 2

        self.lastcall = call["api"]
        # Reset event trigger if the current API isn't Nt[Create|Open]Event
        if call["api"] not in ["NtCreateEvent", "NtOpenEvent"]:
            self.eventtrigger = False

    def on_complete(self):
        if self.vawtrakauto:
            self.malscore += 2
        if self.check_mutex(pattern=r"^\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$", regex=True):
            self.malscore += 2
        if self.malscore >= 10:
            uri_indicators = [
                ".*\/rss\/feed\/stream",
                ".*\/modules\/[a-f0-9]{32}",
            ]
            for ioc in uri_indicators:
                match = self.check_url(pattern=ioc, regex=True)
                if match:
                    buf = {"C2": match}
                    if buf not in self.data:
                        self.data.append(buf)

            return True

        return False
