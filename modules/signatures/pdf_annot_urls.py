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
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        found_URLs = False
        if "static" in self.results and "pdf" in self.results["static"]:
            if "PDF" in self.results["target"]["file"].get("type", ""):
                if "Annot_URLs" in self.results["static"]["pdf"]:
                    for entry in self.results["static"]["pdf"]["Annot_URLs"]:
                        entrylower = entry.lower()
                        if entrylower.endswith(
                            (".zip", ".exe", ".msi", ".bat", ".scr", ".rar", ".com")
                        ) and not entrylower.startswith(
                            "mailto:"
                        ):  # skip mailto: as it can't add attachments
                            skip = False
                            # skip triggering on http:// and https:// links that don't have anything after the domain name
                            # so http://foo.com will be skipped, but http://foo.com/malware.com will not be
                            if entrylower.startswith("http://") and not entrylower.find("/", 8):
                                skip = True
                            elif entrylower.startswith("https://") and not entrylower.find("/", 9):
                                skip = True
                            if skip:
                                self.data.append({"url": entry})
                                found_URLs = True
        return found_URLs
