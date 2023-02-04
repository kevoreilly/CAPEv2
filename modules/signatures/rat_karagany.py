# Copyright (C) 2019 ditekshen
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


class KaraganyEventObjects(Signature):
    name = "karagany_system_event_objects"
    description = "Creates system event objects associated with Karagany/xFrost RAT"
    severity = 3
    categories = ["rat"]
    families = ["Karagany", "xFrost"]
    authors = ["ditekshen"]
    minimum = "0.5"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

    filter_apinames = set(["NtCreateEvent", "NtCreateEventEx"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.event_objects = [
            "__klg__",
            "__pickill__",
            "__klgkillsoft__",
        ]

    def on_call(self, call, process):
        event = self.get_argument(call, "EventName")
        if event:
            for obj in self.event_objects:
                if obj in event:
                    self.match = True
                    self.data.append({"system_event_object": event})
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        return self.match


class KaraganyFiles(Signature):
    name = "karagany_files"
    description = "Creates files/directories associated with Karagany/xFrost RAT"
    severity = 3
    categories = ["rat"]
    families = ["Karagany", "xFrost"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]
    mbcs += ["OC0001", "C0016"]  # micro-behaviour

    def on_complete(self):
        indicators = [
            ".*\\\\up_stat.txt$",
            ".*\\\\stat_ag.txt$",
            ".*\\\\serv_stat.txt$",
            ".*\\\\svchost\d+\.txt$",
            ".*\\\\Update\\\\Tmp\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_file(patten=indicator, regex=True, all=True)
            if match:
                self.data.append({"path": match})
                return True

        return False
