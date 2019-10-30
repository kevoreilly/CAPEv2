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

class NetworkCountryDistribution(Signature):
    name = "network_country_distribution"
    description = "Communicates with IPs located across a large number of unique countries"
    severity = 1
    confidence = 30
    categories = ["network", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    
    filter_analysistypes = set(["file"])

    def run(self):
        countries = []
        if "network" in self.results and "hosts" in self.results["network"]:
            for host in self.results["network"]["hosts"]:
                country = host["country_name"]
                if country and country not in countries:
                    countries.append(country)

        if len(countries) > 5:
            for uniq in countries:
                self.data.append({"country": uniq})

        if self.data:
            return True
        else:
            return False

class NetworkMultipleDirectIPConnections(Signature):
    name = "network_multiple_direct_ip_connections"
    description = "Multiple direct IP connections"
    severity = 2
    confidence = 30
    categories = ["network", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        count = 0
        ips = []
        if "network" in self.results and "hosts" in self.results["network"]:
            for host in self.results["network"]["hosts"]:
                ip = host["ip"]
                hostname = host["hostname"]
                if ip not in ips and not hostname and not ip.startswith(("10.", "172.16.", "192.168.")):
                    ips.append(ip)
                    count += 1

        if count > 5:
            self.data.append({"direct_ip_connections": "Made direct connections to %s unique IP addresses" % (count)})

        if self.data:
            return True
        else:
            return False
