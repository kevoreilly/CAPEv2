# Copyright (C) 2021 Quadrant Information Security, written by Zane C. Bowers-Hadley
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

import dns.resolver
from lib.cuckoo.common.abstracts import Signature

RBLs = (
    "spam.spamrats.com",
    "web.dnsbl.sorbs.net",
    "auth.spamrats.com",
    "http.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "misc.dnsbl.sorbs.net",
    "smtp.dnsbl.sorbs.net",
    "web.dnsbl.sorbs.net",
    "zombie.dnsbl.sorbs.net",
    "block.dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "noserver.dnsbl.sorbs.net",
    "escalations.dnsbl.sorbs.net",
    "noserver.dnsbl.sorbs.net",
    "zen.spamhaus.org",
)

resolver = dns.resolver.Resolver()
resolver.timeout = 0.10


class NetworkQuestionableHost(Signature):
    name = "network_questionable_host"
    description = "Communicates with a host in a RBL"
    severity = 4
    confidence = 80
    categories = ["network", "c2"]
    authors = ["Zane C. Bowers-Hadley"]
    minimum = "1.3"
    enabled = False

    filter_analysistypes = set(["file"])

    def run(self):
        checked = {}
        for key, value in [("hosts", "ip"), ("tcp", "dst"), ("udp", "dst"), ("icmp", "dst"), ("icmp", "src")]:
            for host in self.results.get("network", {}).get(key, []):
                ip = host[value]
                checked[ip] = ""
                if ip.startswith(("10.", "172.16.", "192.168.")):
                    continue
                ipRev = ".".join(ip.split(".")[::-1])
                for rbl in RBLs:
                    try:
                        resolver.query(ipRev + "." + rbl, "A")
                        self.data.append({rbl: ip})
                    except:
                        pass

        if self.data:
            return True

        return False
