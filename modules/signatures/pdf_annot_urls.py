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

class PDF_Annot_URLs(Signature):
    name = "pdf_annot_urls"
    description = "The PDF contains a Link Annotation to a compressed archive or executable file"
    severity = 3
    categories = ["pdf"]
    authors = ["Optiv"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        found_URLs = False
        if "static" in self.results and "pdf" in self.results["static"]:
            if "PDF" in self.results["target"]["file"]["type"]:
                if "Annot_URLs" in self.results["static"]["pdf"]:
                    for entry in self.results["static"]["pdf"]["Annot_URLs"]:
                        entrylower = entry.lower()
                        if entrylower.endswith((".zip", ".exe", ".msi", ".bat", ".scr", ".rar", ".com")):
                            self.data.append({"URL":entry})
                            found_URLs = True
        return found_URLs
