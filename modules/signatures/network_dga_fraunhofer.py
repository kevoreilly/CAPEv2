# Copyright (C) 2020 King-Konsto
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

import os

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.fraunhofer_helper import get_dga_lookup_dict

try:
    from flor import BloomFilter

    HAS_FLOR = True
except ImportError:
    HAS_FLOR = False


class NetworkDGAFraunhofer(Signature):
    name = "network_dga_fraunhofer"
    description = "Likely use of Domain Generation Algorithm (DGA) - Fraunhofer"
    weight = 1
    severity = 3
    categories = ["network"]
    authors = ["kklinger"]
    families = []
    minimum = "1.3"
    ttps = ["T1483"]  # MITRE v6
    ttps += ["T1568", "T1568.002"]  # MITRE v7,8
    ttps += ["U0906"]  # Unprotect
    mbcs = ["B0031"]
    references = [
        "https://dgarchive.caad.fkie.fraunhofer.de",
        "https://github.com/DCSO/flor",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.bloom_location = os.path.join(CUCKOO_ROOT, "data", "dga.bloom")
        # the dga families have produced FPs and will not be able to change weight or malfamily
        # we could consider to already ignore them in create_bloom.py
        self.allowed_families = [
            "Qsnatch",
            "Suppobox",
            "Virut",
        ]

        try:
            # init bloomfilter to be able to do a really quick lookup if a domain is in the bloomfilter
            self.bloom = BloomFilter()
            with open(self.bloom_location, "rb") as f:
                self.bloom.read(f)

            # init dga lookup dict to be able to match dga domain to malware family
            self.dga_lookup_dict = get_dga_lookup_dict()
        except:
            self.bloom = None
            self.dga_lookup_dict = {}

    def run(self):
        if not HAS_FLOR:
            return False

        if not os.path.exists(self.bloom_location):
            return False

        if not (self.bloom and self.dga_lookup_dict):
            return False

        # 1. check if one of the resolved DNS requests is inside our bloomfilter
        hitlist = []
        dnslist = self.results.get("network", {}).get("dns", [])
        if not dnslist:
            return False

        for dns in dnslist:
            request = dns.get("request", "")
            # try to extract domain from full hostname (e.g. foobarbaz.domain.com -> domain.com)
            _domain = ""
            try:
                _domain = request.split(".")[-2:-1][0] + "." + request.split(".")[-1:][0]
            except:
                pass
            # check length of domain to not fire on most likely false positive domains, e.g. "sds.com"
            if _domain and len(_domain) > 7 and _domain != request and _domain.lower().encode("UTF-8") in self.bloom:
                hitlist.append(_domain.lower())
            # fallback to full hostname/request as sometimes we get hostnames as dga domain from the Fraunhofer api
            elif request and request.lower().encode("UTF-8") in self.bloom:
                hitlist.append(request.lower())

        if not hitlist:
            return False

        # 2. if we have hits get malware family
        has_match = False
        for hit in hitlist:
            fam_check = self.dga_lookup_dict.get(hit, "")
            if fam_check:
                tmp_fam = fam_check.split("_")[0]
                if tmp_fam and tmp_fam not in self.families and tmp_fam not in self.allowed_families:
                    self.families.append(tmp_fam)
                    has_match = True

        return has_match
