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

DESCRIPTION = "EvilGrab configuration parser."
AUTHOR = "kevoreilly"

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


def yara_scan(raw_data):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "EvilGrab":
            for item in match.strings:
                addresses[item.identifier] = item.instances[0].offset
    return addresses


def pe_data(pe, va, size):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    return pe.get_data(rva, size)


def string_from_va(pe, offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    string_rva = struct.unpack("i", pe.__data__[offset : offset + 4])[0] - image_base
    string_offset = pe.get_offset_from_rva(string_rva)
    return pe.__data__[string_offset : string_offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


map_offset = {
    "$configure1": [24, 71, 60, 90, 132, 186],
    "$configure2": [27, 78, 67, 91, 133, 188],
    "$configure3": [38, 99, 132, 167, 195],
}


def extract_config(filebuf):
    pe = pefile.PE(data=filebuf, fast_load=False)
    # image_base = pe.OPTIONAL_HEADER.ImageBase
    yara_matches = yara_scan(filebuf)
    end_config = {}
    for key, values in map_offset.keys():
        if not yara_matches.get(key):
            continue

        yara_offset = int(yara_matches[key])

        c2_address = string_from_va(pe, yara_offset + values[0])
        if c2_address:
            end_config["c2_address"] = c2_address
        port = str(struct.unpack("h", filebuf[yara_offset + values[1] : yara_offset + values[1] + 2])[0])
        if port:
            end_config["port"] = [port, "tcp"]
        missionid = string_from_va(pe, yara_offset + values[3])
        if missionid:
            end_config["missionid"] = missionid
        version = string_from_va(pe, yara_offset + values[4])
        if version:
            end_config["version"] = version
        injectionprocess = string_from_va(pe, yara_offset + values[5])
        if injectionprocess:
            end_config["injectionprocess"] = injectionprocess
        if key != "$configure3":
            mutex = string_from_va(pe, yara_offset - values[6])
            if mutex:
                end_config["mutex"] = mutex

    return end_config
