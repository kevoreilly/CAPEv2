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

class DeadConnect(Signature):
    name = "dead_connect"
    description = "Attempts to connect to a dead IP:Port ({0} unique times)"
    severity = 1
    weight = 0
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.connections = set()

    filter_apinames = set(["connect", "ConnectEx", "WSAConnect", "WSAConnectByList"])

    def on_call(self, call, process):
        if not call["status"]:
            ip = self.get_argument(call, "ip")
            port = self.get_argument(call, "port")
            if ip and port:
                self.connections.add("{0}:{1}".format(ip, port))


    def on_complete(self):
        if self.connections:
            failed = len(self.connections)
            self.description = self.description.format(failed)
            if failed > 4:
                self.severity = 2
                self.weight = 1

            for deadip in self.connections:
                ip = deadip.split(":")[0]
                if "hosts" in self.results["network"]:
                    hostdata = next((i for i in self.results["network"]["hosts"] if i["ip"] == ip), None)
                    if hostdata:
                        self.data.append({"IP": "{0} ({1})".format(deadip, hostdata["country_name"])})
                    else:
                        self.data.append({"IP": deadip})

            return True

        return False
