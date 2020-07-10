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
rule IcedID
{
    meta:
        author = "kevoreilly"
        description = "IcedID Payload"
        cape_type = "IcedID Payload"
    strings:
        $crypt1 = {8A 04 ?? D1 C? F7 D? D1 C? 81 E? 20 01 00 00 D1 C? F7 D? 81 E? 01 91 00 00 32 C? 88}
        $crypt2 = {8B 44 24 04 D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 C3}
        $crypt3 = {41 00 8B C8 C1 E1 08 0F B6 C4 66 33 C8 66 89 4? 24 A1 ?? ?? 41 00 89 4? 20 A0 ?? ?? 41 00 D0 E8 32 4? 32}
        $major_ver = {0F B6 05 ?? ?? ?? ?? 6A ?? 6A 72 FF 75 0C 6A 70 50 FF 35 ?? ?? ?? ?? 8D 45 80 FF 35 ?? ?? ?? ?? 6A 63 FF 75 08 6A 67 50 FF 75 10 FF 15 ?? ?? ?? ?? 83 C4 38 8B E5 5D C3}
    condition:
        any of them
}
"""


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "IcedID":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses


def rol(a, i):
    a &= 0xFFFFFFFF
    i &= 0x1F
    x = (((a << i) & 0xFFFFFFFF) | (a >> (32 - i))) & 0xFFFFFFFF
    return x


def ror(a, i):
    i &= 0x1F
    a &= 0xFFFFFFFF
    return (((a >> i) & 0xFFFFFFFF) | (a << ((32 - i)))) & 0xFFFFFFFF


def key_shift(key):
    key = ror(key, 1)
    key = ~key
    key = ror(key, 1)
    key -= 0x120
    key = rol(key, 1)
    key = ~key
    key -= 0x9101
    return key


def iced_decode(data, key, l):
    output = ""
    for i in range(l):
        key = key_shift(key)
        output += chr(struct.unpack("B", data[i : i + 1])[0] ^ (key & 0xFF))
    return output


class IcedID(Parser):

    DESCRIPTION = "IcedID configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        enc_data = None
        try:
            pe = pefile.PE(data=filebuf, fast_load=False)
            for section in pe.sections:
                if section.Name.startswith("bss"):
                    enc_data = section.get_data()
        except:
            pass

        if enc_data:
            key = struct.unpack("I", enc_data[848:852])[0]
            config = iced_decode(enc_data[852:1108], key, 0x100)

            self.reporter.add_metadata("other", {"Bot ID": hex(struct.unpack("I", config[:4])[0])})
            self.reporter.add_metadata("other", {"Minor Version": str(struct.unpack("I", config[4:8])[0])})
            c2_offset = 9
            length = struct.unpack("B", config[c2_offset - 1])[0]
            while length:
                self.reporter.add_metadata("address", config[c2_offset : c2_offset + length])
                c2_offset += length + 1
                length = struct.unpack("B", config[c2_offset - 1])[0]

        major_version = yara_scan(filebuf, "$major_ver")
        if major_version:
            version_offset = int(major_version["$major_ver"])
            self.reporter.add_metadata("other", {"Major Version": str(struct.unpack("B", filebuf[version_offset + 8])[0])})
