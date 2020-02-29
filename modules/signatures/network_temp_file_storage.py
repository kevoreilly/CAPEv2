# Copyright (C) 2019 ditekshen
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

class NetworkTempFileService(Signature):
    name = "network_temp_file_storage"
    description = "Queries or connects to anonymous/temporary file storage service"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

    def run(self):
        domain_indicators = [
            "plik.root.gg",
            "gp.tt",
            "wetransfer.com",
            "send-anywhere.com",
            "sendgb.com",
            "send.firefox.com",
            "volafile.org",
            "uploadfiles.io",
            "sendpace.com",
            "filedropper.com",
            "myairbridge.com",
            "u.teknik.io",
        ]

        found_matches = False
        
        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator):
                self.data.append({"domain" : indicator})
                found_matches = True

        return found_matches
