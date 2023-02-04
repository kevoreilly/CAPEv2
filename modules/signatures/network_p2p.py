# Copyright (C) 2018 Kevin Ross
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


class NetworkP2P(Signature):
    name = "network_p2p"
    description = "Communication to multiple IPs on high port numbers possibly indicative of a peer-to-peer (P2P) or non-standard command and control protocol"
    severity = 2
    categories = ["network", "c2"]
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    evented = True

    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ignoreports = [
            "5938",
            "9001",
            "9030",
            "9050",
            "9051",
            "9150",
            "9151",
        ]

    def on_complete(self):
        servers = set()

        for tcp in self.results.get("network", {}).get("tcp", []):
            if tcp["dport"] > 1023 and tcp["dport"] not in self.ignoreports:
                if not tcp["dst"].startswith(
                    ("0.", "127.", "169.254.", "10.", "220.", "224.", "239.", "240.", "172.16.", "192.168.", "255.255.255.255")
                ):
                    servers.add(tcp["dst"])

        for udp in self.results.get("network", {}).get("udp", []):
            if udp["dport"] > 1023 and udp["dport"] not in self.ignoreports:
                if not udp["dst"].startswith(
                    ("0.", "127.", "169.254.", "10.", "220.", "224.", "239.", "240.", "172.16.", "192.168.", "255.255.255.255")
                ):
                    servers.add(udp["dst"])

        if len(servers) > 4:
            for server in servers:
                self.data.append({"ip": server})

        if len(self.data) > 0:
            return True
        else:
            return False
