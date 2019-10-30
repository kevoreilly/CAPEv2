# Copyright (C) 2015 KillerInstinct
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


class BadSSLCerts(Signature):
    name = "bad_ssl_certs"
    description = "A known bad/malicious SSL cert was accessed"
    severity = 3
    weight = 3
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        # so that we don't modify the base list of BadSSLCerts via the below append
        # which would affect all future invocations of this signature
        self.families = []

        # Add manual indicators here
        sha1_indicators = {
            "6fc7fe77aaac09d078cb50039ec507f964082583": "Dridex C&C",
        }
        matches = dict()
        # Check feeds; an ideal format has a hash and description
        # Get the data from the pre-packaged AbuseCH SSL Feed
        if self.results.get("feeds", {}).get("Bad_SSL_Certs", False):
            with open(self.results["feeds"]["Bad_SSL_Certs"], "r") as feedfile:
                data = feedfile.read().splitlines()
            if data:
                # This feed has results in the form of: SHA1,Description
                for item in data:
                    sha1, desc = item.split(",")
                    # populate the indicators dict
                    if sha1 not in sha1_indicators.keys():
                        sha1_indicators[sha1] = desc

        # Check for TLS fingerprints and then try to find a match
        if self.results.get("suricata", {}).get("tls", False):
            for shahash in self.results["suricata"]["tls"]:
                sha = shahash["fingerprint"].replace(":", "")
                if sha in sha1_indicators.keys() and sha not in matches.keys():
                    matches[sha] = sha1_indicators[sha]

        if matches:
            for item in matches.keys():
                self.families.append(matches[item].split(" ")[0])
                self.data.append({matches[item]: item})
            return True

        return False
