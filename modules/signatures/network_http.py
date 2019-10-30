# Copyright (C) 2013-2015 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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

class NetworkHTTP(Signature):
    name = "network_http"
    description = "Performs some HTTP requests"
    severity = 2
    confidence = 30
    categories = ["http"]
    authors = ["nex","Optiv"]
    minimum = "0.5"

    filter_analysistypes = set(["file"])

    def run(self):
        urls = []
        whitelist = [
            "^http://(crl|ctldl)\.microsoft\.com/.*",
            "^http://www\.microsoft\.com/.*\.crl$",
            "^http://ctldl\.windowsupdate\.com/.*",
            "^http://go\.microsoft\.com/.*",
            ]
        if "file" in self.results["target"]:
            if "PDF" in self.results["target"]["file"]["type"] or self.results["info"]["package"] == "pdf":
                whitelist.append("^http://.*\.adobe\.com/.*")

        if "network" in self.results and "http" in self.results["network"]:
            for req in self.results["network"]["http"]:
                is_whitelisted = False
                for white in whitelist:
                    if re.match(white, req["uri"], re.IGNORECASE):
                        is_whitelisted = True
                if not is_whitelisted and req["uri"] not in urls:
                    urls.append(req["uri"])

        for url in urls:
            self.data.append({"url" : url})

        if urls:
            return True

        return False
