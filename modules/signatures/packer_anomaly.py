# Copyright (C) 2010-2015 Cuckoo Foundation, 2019 Kevin Ross
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

class PackerUnknownPESectionName(Signature):
    name = "packer_unknown_pe_section_name"
    description = "The binary contains an unknown PE section name indicative of packing"
    severity = 2
    categories = ["packer"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"
    ttp = ["T1045"]

    def run(self):
        ret = False
        knownsections = [
            ".aspack",
            ".bss",
            ".crt",
            ".data",
            ".debug",
            ".edata",
            ".eh_fram",
            ".enigma",
            ".gdata",
            ".idata",
            ".mpress",
            ".nate",
            ".ndata",
            ".pdata",
            ".rdata",
            ".reloc",
            ".rsrc",
            ".shared",
            ".text",
            ".titan",
            ".tls",
            ".upx",
            ".vmp",
            ".xdata",
        ]

        for section in self.results.get("static", {}).get("pe", {}).get("sections", []):
            if section["name"].lower() not in knownsections:
                ret = True
                descmsg = "name: {0}, entropy: {1}, characteristics: {2}, raw_size: {3}, virtual_size: {4}".format(section["name"], section["entropy"], section["characteristics"], section["size_of_data"], section["virtual_size"])
                self.data.append({"unknown section": descmsg})

        return ret
