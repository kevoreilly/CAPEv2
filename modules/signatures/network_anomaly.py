# Copyright (C) 2015-2016 KillerInstinct
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

class NetworkAnomaly(Signature):
    name = "network_anomaly"
    description = "Network anomalies occured during the analysis."
    severity = 2
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ipWhitelist = set(["127.0.0.1"])
        self.ipBuffer = list()
        self.ipRex = (r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)"
                       "{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    filter_apinames = set(["getaddrinfo", "InternetConnectA",
                           "InternetConnectW", "connect",
                           "WSAConnect", "GetAddrInfoW"])

    def on_call(self, call, process):
        if call["api"] == "getaddrinfo" or call["api"] == "GetAddrInfoW":
            node = self.get_argument(call, "NodeName")
            if node and node not in self.ipBuffer:
                if re.match(self.ipRex, node) and node not in self.ipWhitelist:
                    self.ipBuffer.append(node)

        elif call["api"].startswith("InternetConnect"):
            ip = self.get_argument(call, "ServerName")
            # Connected to the IP, whitelist it
            if re.match(self.ipRex, ip):
                self.ipWhitelist.add(ip)

        elif call["api"] == "connect":
            self.ipWhitelist.add(self.get_argument(call, "ip"))

        elif call["api"] == "WSAConnect":
            self.ipWhitelist.add(self.get_argument(call, "ip"))

    def on_complete(self):
        ret = False
        # Parse for getaddrinfo with no subsequent connections
        for ip in self.ipBuffer:
            if ip not in self.ipWhitelist:
                self.data.append({"Anomaly": "'%s' getaddrinfo with no actual "
                                             "connection to the IP." % ip })
                ret = True

        return ret
