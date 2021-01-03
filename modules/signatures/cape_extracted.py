# Copyright (C) 2019 Kevin Ross
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


class CAPEExtractedContent(Signature):
    name = "cape_extracted_content"
    description = "CAPE extracted potentially suspicious content"
    severity = 2
    categories = ["generic"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        for cape in self.results.get("CAPE", {}).get("payloads", []) or []:
            yara = cape.get("cape_yara", "") or cape.get("cape_type", "")
            process = cape.get("process_name", "")
            if yara and process:
                self.data.append({process: yara})
                ret = True
                if yara:
                    self.data.append({process: yara})

        return ret

class CAPEExtractedConfig(Signature):
    name = "cape_extracted_config"
    description = "CAPE has extracted a malware configuration"
    severity = 3
    categories = ["malware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        for block in self.results.get("CAPE", {}).get("cape_config", []) or []:
            for malwarename in block.keys():
                self.data.append({"extracted_config": malwarename})
                ret = True

        return ret
