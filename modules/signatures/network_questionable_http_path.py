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

# This is for hitting on HTTP/HTTPS fetches out to hosts that have
# likely been compromised.

# common_dirs contains a lists of directorys that are commonly given
# 777 perms and get drek written to them. Or with out 777 written to
# via the a compromised PHP script or the like.

from lib.cuckoo.common.abstracts import Signature

# common dir names to check for the usage of
common_dirs = (
    "/wp-content/",
    "/template/",
    "/tmp/",
    "/temp/",
    "/data/",
)
# executable or archive files to checked for being pulled down
common_extensions = (
    ".zip",
    ".exe",
    ".com",
    ".bz2",
    ".gz",
    ".bz",
    ".ace",
    ".tar",
    ".tgz",
    ".tbz",
    ".7z",
    ".rar",
)


class NetworkQuestionableHttpPath(Signature):
    name = "network_questionable_http_path"
    description = "Makes a suspicious HTTP request to a commonly exploitable directory with questionable file ext"
    severity = 3
    confidence = 100
    categories = ["network"]
    authors = ["Zane C. Bowers-Hadley"]
    minimum = "1.3"
    enabled = True

    filter_analysistypes = set(["file"])

    def find_dir_n_type(self, uri):
        if any([uri.find(common_dir) for common_dir in common_dirs]) and uri.endswith(common_extensions):
            return True
        return False

    def run(self):
        for host in self.results.get("network", {}).get("http", []) or []:
            if self.find_dir_n_type(host["path"].lower()):
                self.data.append({"url": host["uri"]})
        if self.data:
            return True
        else:
            return False


class NetworkQuestionableHttpsPath(Signature):
    name = "network_questionable_https_path"
    description = "Makes a suspicious HTTPS request to a commonly exploitable directory with questionable file ext"
    severity = 3
    confidence = 100
    categories = ["network"]
    authors = ["Zane C. Bowers-Hadley"]
    minimum = "1.3"
    enabled = True

    filter_analysistypes = set(["file"])

    def run(self):
        for host in self.results.get("network", {}).get("https", []) or []:
            if self.find_dir_n_type(host["path"].lower()):
                self.data.append({"url": host["uri"]})
        if self.data:
            return True
        else:
            return False
