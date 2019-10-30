# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class NetworkDGA(Signature):
    name = "network_dga"
    description = "Likely use of Domain Generation Algorithm (DGA)"
    severity = 3
    categories = ["network"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        resolv_success = 0
        dga_score = 0

        if "network" in self.results:
            if "dns" in self.results["network"]:
                if len(self.results["network"]["dns"]) > 0:
                    for dns in self.results["network"]["dns"]:
                        for ans in dns["answers"]:
                            if ans["type"] == "NXDOMAIN":
                                if dns["request"].count('.') == 1:
                                    num_cnt = sum(c.isdigit() for c in dns["request"])
                                    # whitelist domains with potentially the year in the name
                                    if num_cnt > 1 and "20" not in dns["request"]:
                                        dga_score += num_cnt
                                    if len(dns["request"]) > 20:
                                        dga_score += 2
                                    if len(dns["request"]) > 30:
                                        dga_score += 10
                                    if dns["request"].endswith((".su", ".kz", ".cc", ".ws", ".tk", ".so", ".to")):
                                        dga_score += 2
                                    dga_score += 1
                            else:
                                resolv_success += 1

        # to deal with old malware with completely dead domains
        if not resolv_success:
            dga_score = 0
        else:
            dga_score /= resolv_success

        if dga_score > 4:
            return True
