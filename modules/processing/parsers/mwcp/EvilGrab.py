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
rule EvilGrab
{
    meta:
        author = "kev"
        description = "EvilGrab configuration function"
        cape_type = "EvilGrab Payload"
    strings:
        $configure1 = {8D 44 24 ?? 50 6A 01 E8 ?? ?? ?? ?? 85 C0 74 07 33 C0 E9 9? 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 07 59 73 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68}
        $configure2 = {8D 44 24 ?? 50 6A 01 E8 ?? ?? ?? ?? 85 C0 74 07 33 C0 E9 9? 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 07 59 73 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83}
        $configure3 = {8D 95 60 ?? ?? ?? 52 6A 01 E8 ?? ?? ?? ?? 85 C0 74 13 33 C0 8B 4D F4 64 89 0D 00 00 00 00 5F 5E 5B 8B E5 5D C3 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE}

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        $configure1 or $configure2 or $configure3
}

"""

MAX_STRING_SIZE = 65


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "EvilGrab":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses


def pe_data(pe, va, size):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    data = pe.get_data(rva, size)
    return data


def string_from_va(pe, offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    string_rva = struct.unpack("i", pe.__data__[offset : offset + 4])[0] - image_base
    string_offset = pe.get_offset_from_rva(string_rva)
    string = pe.__data__[string_offset : string_offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string


class evilgrab(Parser):

    DESCRIPTION = "EvilGrab configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        type1 = yara_scan(filebuf, "$configure1")
        type2 = yara_scan(filebuf, "$configure2")
        type3 = yara_scan(filebuf, "$configure3")

        if type1:
            yara_offset = int(type1["$configure1"])

            c2_address = string_from_va(pe, yara_offset + 24)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

            port = str(struct.unpack("h", filebuf[yara_offset + 71 : yara_offset + 73])[0])
            if port:
                self.reporter.add_metadata("port", [port, "tcp"])

            missionid = string_from_va(pe, yara_offset + 60)
            if missionid:
                self.reporter.add_metadata("missionid", missionid)

            version = string_from_va(pe, yara_offset + 90)
            if version:
                self.reporter.add_metadata("version", version)

            injectionprocess = string_from_va(pe, yara_offset + 132)
            if injectionprocess:
                self.reporter.add_metadata("injectionprocess", injectionprocess)

            mutex = string_from_va(pe, yara_offset - 186)
            if mutex:
                self.reporter.add_metadata("mutex", mutex)

        if type2:
            yara_offset = int(type2["$configure2"])

            c2_address = string_from_va(pe, yara_offset + 24)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

            port = str(struct.unpack("h", filebuf[yara_offset + 78 : yara_offset + 80])[0])
            if port:
                self.reporter.add_metadata("port", [port, "tcp"])

            missionid = string_from_va(pe, yara_offset + 67)
            if missionid:
                self.reporter.add_metadata("missionid", missionid)

            version = string_from_va(pe, yara_offset + 91)
            if version:
                self.reporter.add_metadata("version", version)

            injectionprocess = string_from_va(pe, yara_offset + 133)
            if injectionprocess:
                self.reporter.add_metadata("injectionprocess", injectionprocess)

            mutex = string_from_va(pe, yara_offset - 188)
            if mutex:
                self.reporter.add_metadata("mutex", mutex)

        if type3:
            yara_offset = int(type3["$configure3"])

            c2_address = string_from_va(pe, yara_offset + 38)
            if c2_address:
                self.reporter.add_metadata("c2_address", c2_address)

            port = str(struct.unpack("h", filebuf[yara_offset + 99 : yara_offset + 101])[0])
            if port:
                self.reporter.add_metadata("port", [port, "tcp"])

            missionid = string_from_va(pe, yara_offset + 132)
            if missionid:
                self.reporter.add_metadata("missionid", missionid)

            version = string_from_va(pe, yara_offset + 167)
            if version:
                self.reporter.add_metadata("version", version)

            injectionprocess = string_from_va(pe, yara_offset + 195)
            if injectionprocess:
                self.reporter.add_metadata("injectionprocess", injectionprocess)
