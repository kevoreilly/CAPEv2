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

class Cerber_APIs(Signature):
    name = "cerber_behavior"
    description = "Exhibits behavior characteristic of Cerber ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["cerber"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.udpCount = dict()
        self.lastIp = str()
        self.lastData = str()
        self.skip = False

    filter_apinames = set(["socket", "sendto"])

    def on_call(self, call, process):
        if self.skip:
            return None

        if call["status"]:
            if call["api"] == "socket":
                proto = self.get_argument(call, "protocol")
                stype = self.get_argument(call, "type")
                if proto == "17" and stype == "2":
                    sock = str(self.get_argument(call, "socket"))
                    self.udpCount[sock] = 0

            elif call["api"] == "sendto":
                sock = str(self.get_argument(call, "socket"))
                if sock in self.udpCount:
                    ip = self.get_argument(call, "ip")
                    if not self.lastIp:
                        self.lastIp = ip
                    buf = self.get_argument(call, "buffer")
                    if not self.lastData:
                        self.lastData = buf
                    if ip != self.lastIp and buf == self.lastData:
                        self.udpCount[sock] += 1
                        if self.udpCount[sock] >= 300:
                            self.skip = True
                    self.lastIp = ip

        return None

    def on_complete(self):
        badness = 0
        if self.udpCount:
            badness += 9

        fileiocs = [
            r".*\\AppData\\Roaming\\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\.*\.exe$",
        ]
        for ioc in fileiocs:
            if self.check_write_file(pattern=ioc, regex=True):
                badness += 2

        regiocs = [
            r".*\\Printers\\.*\\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\Component_01",
            r".*\\Printers\\.*\\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\Component_02",
        ]
        for ioc in regiocs:
            if self.check_write_key(pattern=ioc, regex=True):
                badness += 4

        mutexiocs = [
            r"^shell\.\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$",
        ]
        for ioc in mutexiocs:
            if self.check_mutex(pattern=ioc, regex=True):
                badness += 2

        if badness >= 10:
            return True

        return False
