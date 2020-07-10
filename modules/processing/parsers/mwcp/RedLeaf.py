# Copyright (C) 2017 Kevin O'Reilly kevin.oreilly@contextis.co.uk
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
rule RedLeaf
{
    meta:
        author = "kev"
        description = "RedLeaf configuration parser."
        cape_type = "RedLeaf Payload"
    strings:
        $crypto = {6A 10 B8 ?? ?? ?? 10 E8 ?? ?? 01 00 8B F1 89 75 E4 8B 7D 08 83 CF 07 81 FF FE FF FF 7F 76 05 8B 7D 08 EB 29 8B 4E 14 89 4D EC D1 6D EC 8B C7 33 D2 6A 03 5B F7 F3 8B 55 EC 3B D0 76 10 BF FE FF FF}
        $decrypt_config = {55 8B EC 83 EC 20 A1 98 9F 03 10 33 C5 89 45 FC 56 33 F6 33 C0 80 B0 ?? ?? ?? ?? ?? 40 3D ?? ?? ?? ?? 72 F1 68 70 99 03 10 56 56 FF 15 2C 11 03 10 FF 15 B8 11 03 10 3D B7 00 00 00 75 06 56 E8 5F 9E}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        $crypto and $decrypt_config
}

"""

MAX_STRING_SIZE = 64
MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "RedLeaf":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses


def pe_data(pe, va, size):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    data = pe.get_data(rva, size)
    return data


def string_from_offset(buffer, offset):
    string = buffer[offset : offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string


def unicode_string_from_offset(buffer, offset):
    string = buffer[offset : offset + MAX_STRING_SIZE].split(b"\x00\x00")[0]
    return string


class redleaf(Parser):

    DESCRIPTION = "RedLeaf configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=self.file_object.file_data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        decrypt_config = yara_scan(filebuf, "$decrypt_config")

        if decrypt_config:
            yara_offset = int(decrypt_config["$decrypt_config"])
        else:
            return

        config_rva = struct.unpack("i", filebuf[yara_offset + 23 : yara_offset + 27])[0] - image_base

        config_offset = pe.get_offset_from_rva(config_rva)

        xor_key = struct.unpack("b", filebuf[yara_offset + 27 : yara_offset + 28])[0]

        config_size = struct.unpack("i", filebuf[yara_offset + 30 : yara_offset + 34])[0]

        config = "".join([chr(xor_key ^ ord(x)) for x in filebuf[config_offset : config_offset + config_size]])

        c2_address = config[8 : 8 + MAX_IP_STRING_SIZE]
        if c2_address != "":
            self.reporter.add_metadata("c2_address", c2_address)

        c2_address = config[0x48 : 0x48 + MAX_IP_STRING_SIZE]
        if c2_address != "":
            self.reporter.add_metadata("c2_address", c2_address)

        c2_address = config[0x88 : 0x88 + MAX_IP_STRING_SIZE]
        if c2_address != "":
            self.reporter.add_metadata("c2_address", c2_address)

        missionid = string_from_offset(config, 0x1EC)
        if missionid:
            self.reporter.add_metadata("missionid", missionid)

        mutex = unicode_string_from_offset(config, 0x508)
        if mutex:
            self.reporter.add_metadata("mutex", mutex)

        key = string_from_offset(config, 0x832)
        if key:
            self.reporter.add_metadata("key", key)
