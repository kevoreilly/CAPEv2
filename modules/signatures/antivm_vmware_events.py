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

class VMwareDetectEvent(Signature):
    name = "antivm_vmware_events"
    description = "Detects VMware through Opening/Creating VMware specific events"
    severity = 3
    categories = ["anti-vm"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.matches = list()

    filter_apinames = set(["NtCreateEvent", "NtOpenEvent"])

    def on_call(self, call, process):
        vmware_events = [
            "VMwareToolsDumpStateEvent_vmusr",
            "VMwareToolsQuitEvent_vmusr",
            "VMwareToolsDumpStateEvent_vmsvc",
            "VMwareToolsQuitEvent_vmsvc",
            "VMToolsWindowEvent",
            "VMToolsHookQueueEvent",
        ]

        event = self.get_argument(call, "EventName")
        for check in vmware_events:
            if check in event:
                self.matches.append(event)

    def on_complete(self):
        ret = False
        if self.matches:
            ret = True
            for item in self.matches:
                self.data.append({"Event": item})

        return ret
