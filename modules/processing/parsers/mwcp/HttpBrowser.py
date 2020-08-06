# Copyright (C) 2015 Kevin O'Reilly kevin.oreilly@contextis.co.uk
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
rule HttpBrowser
{
    meta:
        author = "kev"
        description = "HttpBrowser C2 connect function"
        cape_type = "HttpBrowser Payload"
    strings:
        $connect_1 = {33 C0 68 06 02 00 00 66 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 5? 50 E8 ?? ?? 00 00 8B 35 ?? ?? ?? ?? 83 C4 0C 6A 01 BB ?? ?? ?? ?? 53 FF D6 59 50 BF}
        $connect_2 = {33 C0 68 06 02 00 00 66 89 ?? ?? ?? 8D ?? ?? ?? 5? 50 E8 ?? ?? 00 00 8B 35 ?? ?? ?? ?? 83 C4 0C 6A 01 BB ?? ?? ?? ?? 53 FF D6 59 50 BF}
        $connect_3 = {68 40 1F 00 00 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? BB ?? ?? ?? ?? 53 FF D6 59 50 BF ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 59 59}
        $connect_4 = {33 C0 57 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 6A 01 FF 75 08 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        $connect_1 or $connect_2 or $connect_3 or $connect_4
}

"""

MAX_STRING_SIZE = 67


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "HttpBrowser":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses


def pe_data(pe, va, size):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    data = pe.get_data(rva, size)
    return data


def ascii_from_va(pe, offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    string_rva = struct.unpack("i", pe.__data__[offset : offset + 4])[0] - image_base
    string_offset = pe.get_offset_from_rva(string_rva)
    string = pe.__data__[string_offset : string_offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string


def unicode_from_va(pe, offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    string_rva = struct.unpack("i", pe.__data__[offset : offset + 4])[0] - image_base
    string_offset = pe.get_offset_from_rva(string_rva)
    string = pe.__data__[string_offset : string_offset + MAX_STRING_SIZE].split(b"\x00\x00")[0]
    return string


class evilgrab(Parser):

    DESCRIPTION = "HttpBrowser configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=self.file_object.file_data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        type1 = yara_scan(filebuf, "$connect_1")
        type2 = yara_scan(filebuf, "$connect_2")
        type3 = yara_scan(filebuf, "$connect_3")
        type4 = yara_scan(filebuf, "$connect_4")

        if type1:
            yara_offset = int(type1["$connect_1"])

            port = ascii_from_va(pe, yara_offset + 39)
            if port:
                self.reporter.add_metadata("port", [port, "tcp"])

            c2_address = unicode_from_va(pe, yara_offset + 49)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

        if type2:
            yara_offset = int(type2["$connect_2"])

            port = ascii_from_va(pe, yara_offset + 35)
            if port:
                self.reporter.add_metadata("port", [port, "tcp"])

            c2_address = unicode_from_va(pe, yara_offset + 45)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

        if type3:
            yara_offset = int(type3["$connect_3"])

            port = ascii_from_va(pe, yara_offset + 18)
            if port:
                self.reporter.add_metadata("port", [port, "tcp"])

            c2_address = unicode_from_va(pe, yara_offset + 28)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

            c2_address = unicode_from_va(pe, yara_offset + 66)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

        if type4:
            yara_offset = int(type4["$connect_4"])

            c2_address = unicode_from_va(pe, yara_offset + 35)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

            filepath = unicode_from_va(pe, yara_offset + 90)
            if filepath:
                self.reporter.add_metadata("filepath", filepath)

            injectionprocess = unicode_from_va(pe, yara_offset - 13)
            if injectionprocess:
                self.reporter.add_metadata("injectionprocess", injectionprocess)
