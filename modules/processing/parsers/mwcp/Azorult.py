# Copyright (C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
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

from mwcp.parser import Parser
import struct
import pefile
import yara

rule_source = """
rule Azorult
{
    meta:
        author = "kevoreilly"
        description = "Azorult Payload"
        cape_type = "Azorult Payload"
    strings:
        $ref_c2 = {6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF 55 F0 8B D8 C7 47 10 ?? ?? ?? ?? 90 C7 45 B0 C0 C6 2D 00 6A 04 8D 45 B0 50 6A 06 53 FF 55 D4}
   condition:
        uint16(0) == 0x5A4D and all of them
}

"""

MAX_STRING_SIZE = 32


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Azorult":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses


def string_from_offset(data, offset):
    string = data[offset : offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string


class Azorult(Parser):
    DESCRIPTION = "Azorult configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        ref_c2 = yara_scan(filebuf, "$ref_c2")
        if ref_c2 is None:
            return

        ref_c2_offset = int(ref_c2["$ref_c2"])
        if ref_c2_offset is None:
            return

        c2_list_va = struct.unpack("i", filebuf[ref_c2_offset + 21 : ref_c2_offset + 25])[0]
        c2_list_rva = c2_list_va - image_base

        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
            print(err)

        c2_domain = string_from_offset(filebuf, c2_list_offset)
        if c2_domain:
            self.reporter.add_metadata("address", c2_domain)
