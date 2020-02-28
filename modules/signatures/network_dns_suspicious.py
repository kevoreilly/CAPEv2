# Copyright (C) 2020 ditekshen
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

class NetworkDNSTunnelingRequest(Signature):
    name = "network_dns_tunneling_request"
    description = "Generates suspicious DNS queries indicative of DNS tunneling"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1048", "T1071", "T1094", "T1320"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.qcount = int()
        self.match = False
        # base16, bas32, bas32hex, bas64
        self.patterns = [
            re.compile(".*(\.)?[A-Fa-f0-9-_]{12,}.*"),
            re.compile(".*(\.)?[A-Z2-7-_]{15,}.*"),
            re.compile(".*(\.)?[A-V0-9-_]{15,}.*"),
            re.compile(".*(\.)?[A-Za-z0-9-_]{20,}.*"),
        ]
        self.dwhitelist = [
            ".inaddr.arpa",
            ".ip6.arpa",
            ".apple.com",
        ]

    filter_apinames = set(["DnsQuery_A", "DnsQuery_W"])

    def on_call(self, call, process):
        qtype = self.get_argument(call, "Type")
        qname = self.get_argument(call, "Name")
        if qtype and qname:
            labels = qname.split(".")
            if labels:
                mdomain = labels[len(labels) - 2] + "." + labels[len(labels) - 1]
                if mdomain:
                    if mdomain not in self.dwhitelist:
                        for pat in self.patterns:
                            if re.match(pat, qname):
                                self.qcount += 1
                                self.match = True
                        if len(qname) > 50:
                            self.qcount += 1
                            self.match = True

    def on_complete(self):
        if self.match and self.qcount > 5:
            return True

        return False

class NetworkDNSIDN(Signature):
    name = "network_dns_idn"
    description = "Generates a DNS query to IDN/Punycode domain"
    severity = 2
    categories = ["network",]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    filter_apinames = set(["DnsQueryA"])

    def on_call(self, call, process):
        qname = self.get_argument(call, "Name")
        if qname:
            if qname.startswith("xn--"):
                self.match = True

    def on_complete(self):
        return self.match

class NetworkDNSSuspiciousQueryType(Signature):
    name = "network_dns_suspicious_querytype"
    description = "Generates less common DNS request type"
    severity = 2
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1048", "T1071", "T1094", "T1320"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.qtype_whitelist = [1, 2, 5, 10, 12, 15, 16, 28, 255]

    filter_apinames = set(["DnsQueryA"])

    def on_call(self, call, process):
        self.qtype = self.get_argument(call, "Type")
        if self.qtype:
            if self.qtype not in self.qtype_whitelist:
                self.match = True

    def on_complete(self):
        return self.match