# Copyright (C) 2017 Kevin Ross
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

class NetworkExcessiveUDP(Signature):
    name = "network_excessive_udp"
    description = "Creates an excessive number of UDP connection attempts to external IP addresses"
    severity = 2
    confidence = 30
    categories = ["udp", "cnc", "p2p", "recon"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        whitelistports = ["53", "123", "500"]
        uniqueips = 0
        ips = []

        if "network" in self.results and "udp" in self.results["network"]:
            for udp in self.results["network"]["udp"]:
                dstip = udp["dst"]
                dstport = udp["dport"]
                if uniqueips > 100:
                    return True
                    break
                if dstip not in ips and dstport not in whitelistports and not dstip.startswith(("127.", "10.", "172.16.", "192.168.")):
                    ips.append(dstip)
                    uniqueips += 1
           
        return False
