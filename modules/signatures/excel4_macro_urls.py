# Copyright (C) 2020 doomedraven
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


class Excel4MacroUrls(Signature):
    name = "excel4_macro_urls"
    description = "URLs from Excel 4.0 XLM Macro(s)"
    weight = 3
    severity = 3
    categories = ["macro", "office"]
    authors = ["doomedraven"]
    minimum = "2.0"
    evented = False
    ttps = ["T1137", "T1137.001"]  # MITRE v6,7,8

    def run(self):
        ret = False
        for line in self.results.get("static", {}).get("office", {}).get("XLMMacroDeobfuscator", []) or []:
            if "URLDownloadToFileA" not in line:
                continue

            blocks = line.split(",")
            if len(blocks) != 10:
                continue
            url = blocks[6].replace('"', "").replace("'", "")
            if url.startswith("http"):
                self.data.append({"url": url})
                ret = True

        return ret
