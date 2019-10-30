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
        if "CAPE" in self.results:
            for cape in self.results.get("CAPE", []):
                capetype = cape.get("cape_type", "")
                yara = cape.get("cape_yara", "")
                process = cape.get("process_name", "")
                if capetype and process:
                    self.data.append({process: capetype})
                    ret = True
                    if yara:
                        self.data.append({process: yara})

            return ret
