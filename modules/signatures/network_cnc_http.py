# Copyright (C) 2016 Kevin Ross
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


class NetworkHTTPPOST(Signature):
    name = "network_http_post"
    description = "Sends data using the HTTP POST Method"
    severity = 2
    # Migrated by @CybercentreCanada
    categories = ["network", "c2"]
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    evented = True

    filter_analysistypes = set(["file"])

    def on_complete(self):
        safelist = [
            "microsoft.com",
            "windowsupdate\.com",
            "adobe.com",
        ]

        if "network" in self.results and "http" in self.results["network"]:
            for http in self.results["network"]["http"]:
                if any(safelisted in http["host"] for safelisted in safelist):
                    continue

                if http["method"] == "POST":
                    request = "%s %s" % (http["method"], http["uri"])
                    self.data.append({"request": request})

        if len(self.data) > 0:
            return True
        else:
            return False


class NetworkCnCHTTP(Signature):
    name = "network_cnc_http"
    description = "HTTP traffic contains suspicious features which may be indicative of malware related traffic"
    severity = 2
    confidence = 30
    weight = 0
    categories = ["network", "c2"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.001"]  # MITRE v7,8
    mbcs = ["OB0004", "B00330"]
    mbcs += ["OC0006", "C0002"]  # micro-behaviour

    filter_analysistypes = set(["file"])

    def run(self):
        whitelist = [
            "^http://.*\.microsoft\.com/.*",
            "^http://.*\.windowsupdate\.com/.*",
            "http://.*\.adobe\.com/.*",
        ]

        # HTTP request Features. Done like this due to for loop appending data each time instead of once so we wait to end of checks to add summary of anomalies
        post_noreferer = False
        post_nouseragent = False
        get_nouseragent = False
        version1 = False
        iphost = False

        # Scoring
        cnc_score = 0
        suspectrequest = []

        if "network" in self.results and "http" in self.results["network"]:
            for req in self.results["network"]["http"]:
                is_whitelisted = False
                for white in whitelist:
                    if re.match(white, req["uri"], re.IGNORECASE):
                        is_whitelisted = True

                # Check HTTP features
                request = req["uri"]
                ip = re.compile("^http\:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                if not is_whitelisted and req["method"] == "POST" and "Referer:" not in req["data"]:
                    post_noreferer = True
                    cnc_score += 1

                if not is_whitelisted and req["method"] == "POST" and "User-Agent:" not in req["data"]:
                    post_nouseragent += 1
                    cnc_score += 1

                if not is_whitelisted and req["method"] == "GET" and "User-Agent:" not in req["data"]:
                    get_nouseragent = True
                    cnc_score += 1

                if not is_whitelisted and req["version"] == "1.0":
                    version1 = True
                    cnc_score += 1

                if not is_whitelisted and ip.match(request):
                    iphost = True
                    cnc_score += 1

                if not is_whitelisted and cnc_score > 0:
                    if suspectrequest.count(request) == 0:
                        suspectrequest.append(request)

        if post_noreferer:
            self.data.append({"post_no_referer": "HTTP traffic contains a POST request with no referer header"})
            self.weight += 1

        if post_nouseragent:
            self.data.append({"post_no_useragent": "HTTP traffic contains a POST request with no user-agent header"})
            self.weight += 1

        if get_nouseragent:
            self.data.append({"get_no_useragent": "HTTP traffic contains a GET request with no user-agent header"})
            self.weight += 1

        if version1:
            self.data.append({"http_version_old": "HTTP traffic uses version 1.0"})
            self.weight += 1

        if iphost:
            self.data.append({"ip_hostname": "HTTP connection was made to an IP address rather than domain name"})
            self.weight += 1

        if self.weight and len(suspectrequest) > 0:
            for request in suspectrequest:
                self.data.append({"suspicious_request": request})

        if self.weight:
            return True

        return False


class NetworkIPEXE(Signature):
    name = "network_ip_exe"
    description = "Executable is attempted to be downloaded from an IP"
    severity = 5
    categories = ["network", "downloader"]
    authors = ["@CybercentreCanada"]
    minimum = "1.2"

    def run(self):
        indicator = "(https?://)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\.exe"
        # Downloading an EXE from an IP is ALWAYS SKETCHY
        matches = self.check_url(pattern=indicator, regex=True, all=True)
        if matches:
            for match in matches:
                self.data.append({"request": match})

        if len(self.data) > 0:
            return True
        else:
            return False
