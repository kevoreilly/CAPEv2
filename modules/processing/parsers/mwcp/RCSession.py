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
rule RCSession
{
    meta:
        author = "kevoreilly"
        description = "RCSession Payload"
        cape_type = "RCSession Payload"
    strings:
        $a1 = {56 33 F6 39 74 24 08 7E 4C 53 57 8B F8 2B FA 8B C6 25 03 00 00 80 79 05 48 83 C8 FC 40 83 E8 00 74 19 48 74 0F 48 74 05 6B C9 09 EB 15 8B C1 C1 E8 02 EB 03 8D 04 09 2B C8}
        $a2 = {83 C4 10 85 C0 74 ?? BE ?? ?? ?? ?? 89 74 24 10 E8 ?? ?? ?? ?? 6A 03 68 48 0B 00 00 56 53 57 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 18 85 C0 74 18 E8 ?? ?? ?? ?? 6A 03 68 48}
    condition:
        (any of ($a*))
}

"""

MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0
UINT_MAX = 0xFFFFFFFF


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "RCSession":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses


def unicode_string_from_offset(buffer, offset, max):
    string = buffer[offset : offset + max].decode("utf-16")
    return string


def decode(ciphertext, size, key):

    if size == 0:
        return

    v4 = 0
    decoded_chars = bytearray(size)

    while v4 < size:
        if v4 % 4 == 0:
            key = (key + (key >> 4)) & UINT_MAX
        elif v4 % 4 == 1:
            v6 = (2 * key) & UINT_MAX
            key = (key - v6) & UINT_MAX
        elif v4 % 4 == 2:
            v6 = (key >> 2) & UINT_MAX
            key = (key - v6) & UINT_MAX
        else:
            key = (key * 9) & UINT_MAX
        decoded_chars[v4] = struct.unpack("B", ciphertext[v4 : v4 + 1])[0] ^ (key & 0xFF)
        v4 = v4 + 1

    return decoded_chars


class RCSession(Parser):

    DESCRIPTION = "RCSession configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=self.file_object.file_data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        decrypt_config = yara_scan(filebuf, "$a2")

        if decrypt_config:
            yara_offset = int(decrypt_config["$a2"])
        else:
            return

        config_rva = struct.unpack("i", filebuf[yara_offset + 8 : yara_offset + 12])[0] - image_base
        config_offset = pe.get_offset_from_rva(config_rva)
        size = struct.unpack("i", filebuf[yara_offset + 88 : yara_offset + 92])[0]
        key = struct.unpack("i", filebuf[config_offset + 128 : config_offset + 132])[0]

        config = decode(filebuf[config_offset : config_offset + size], size, key)

        c2_address = str(config[156 : 156 + MAX_IP_STRING_SIZE])
        if c2_address != "":
            self.reporter.add_metadata("c2_address", c2_address)

        c2_address = str(config[224 : 224 + MAX_IP_STRING_SIZE])
        if c2_address != "":
            self.reporter.add_metadata("c2_address", c2_address)

        installdir = unicode_string_from_offset(bytes(config), 0x2A8, 128)
        if installdir != "":
            self.reporter.add_metadata("directory", installdir)

        executable = unicode_string_from_offset(config, 0x4B0, 128)
        if executable != "":
            self.reporter.add_metadata("filename", executable)

        servicename = unicode_string_from_offset(config, 0x530, 128)
        if servicename != "":
            self.reporter.add_metadata("servicename", servicename)

        displayname = unicode_string_from_offset(config, 0x738, 128)
        if displayname != "":
            self.reporter.add_metadata("servicedisplayname", displayname)

        description = unicode_string_from_offset(config, 0x940, 512)
        if description != "":
            self.reporter.add_metadata("servicedescription", description)
