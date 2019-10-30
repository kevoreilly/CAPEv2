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

struct_pat = re.compile(r"\\x11\"3D\d{2}\.\d{2}(?:[A-Za-z]|\\x00)(?:\\x00){2}(?:\d{4}|(?:\\x00){4})(?:\\x00){12}http")
url_pat = re.compile(r"(https?://[^\|]+)(?:\||\\x00)")

class Hancitor_APIs(Signature):
    name = "hancitor_behavior"
    description = "Exhibits behavior characteristic of Hancitor downloader"
    weight = 3
    severity = 3
    categories = ["downloader"]
    families = ["hancitor", "chanitor", "tordal"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.c2s = []
        self.found = False
        self.lastapi = str()
        self.suspended = dict()

    filter_apinames = set(["CreateProcessInternalW", "WriteProcessMemory", "NtClose"])

    def getWrittenUrls(self, data):
        memstruct = None
        if not self.found:
            memstruct = struct_pat.search(data)
            if memstruct:
                self.found = True
        urls = url_pat.findall(data)
        if memstruct and urls:
            sanitized = list()
            for url in urls:
                sanitized.append(url.replace("\\x00", ""))
            return sanitized

        return []

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            flags = int(self.get_argument(call, "CreationFlags"), 16)
            if flags & 0x4:
                handle = self.get_argument(call, "ProcessHandle")
                self.suspended[handle] = self.get_argument(call, "ProcessId")

        elif call["api"] == "WriteProcessMemory":
            if self.lastapi == "WriteProcessMemory":
                handle = self.get_argument(call, "ProcessHandle")
                if handle in self.suspended:
                    buf = self.get_argument(call, "Buffer")
                    if buf:
                        check = self.getWrittenUrls(buf)
                        if len(check) >= 2:
                            self.c2s = check

        elif call["api"] == "NtClose":
            if call["status"]:
                handle = self.get_argument(call, "Handle")
                if handle in self.suspended:
                    del self.suspended[handle]

        self.lastapi = call["api"]

        return None

    def on_complete(self):
        ret = self.found
        if self.c2s:
            for url in self.c2s:
                c2 = {"C2": url}
                if url not in self.data:
                    self.data.append(c2)

        return ret
