# Copyright (C) 2017 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
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
import os.path

rule_source = """
rule Redsip
{
    meta:
        author = "kevoreilly"
        description = "Redsip Payload"
        cape_type = "Redsip Payload"
    strings:
        $decrypt = {8B 45 F8 99 B9 0A 00 00 00 F7 F9 85 D2 75 1F 8A 55 10 88 55 FF 8B 45 08 03 45 F8 0F BE 08 0F BE 55 FF 33 CA 8B 45 08 03 45 F8 88 08 EB C1}
        $call_decrypt = {8B 85 E0 FD FF FF 50 FF 15 ?? ?? ?? ?? C7 85 E0 FD FF FF FF FF FF FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8}
    condition:
        uint16(0) == 0x5A4D and $decrypt and $call_decrypt
}

"""

MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Redsip":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses


def unicode_string_from_offset(buffer, offset, max):
    try:
        string = buffer[offset : offset + max].decode("utf-16")
    except:
        return
    return string


def decode(ciphertext, size, key):

    if size == 0:
        return

    key = key & 0xFF
    decoded_chars = bytearray(size)
    count = 0

    while count < size:
        if count % 10:
            decoded_chars[count] = struct.unpack("B", ciphertext[count : count + 1])[0] ^ ((key + count) & 0xFF)
        else:
            decoded_chars[count] = struct.unpack("B", ciphertext[count : count + 1])[0] ^ key
        count = count + 1

    return decoded_chars


def process_file(filepath, filesize, key):

    with open(filepath, "r") as file_open:
        filedata = file_open.read()

    if len(filedata) != filesize:
        return

    return decode(filedata, filesize, key)


class Redsip(Parser):

    DESCRIPTION = "Redsip configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=self.file_object.file_data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        call_decrypt = yara_scan(filebuf, "$call_decrypt")

        if call_decrypt:
            yara_offset = int(call_decrypt["$call_decrypt"])
        else:
            return

        key = struct.unpack("B", filebuf[yara_offset + 24 : yara_offset + 25])[0]
        size = struct.unpack("I", filebuf[yara_offset + 26 : yara_offset + 30])[0]
        config_found = False

        # The config is in a dropped file
        if self.reporter.analysis_path:
            dropped_path = os.path.join(self.reporter.analysis_path, "files")
            for f in os.listdir(dropped_path):
                path = os.path.join(dropped_path, f)
                if os.path.isfile(path):
                    filesize = os.path.getsize(path)
                    # We select based on size match with the code
                    if filesize == size:
                        config = process_file(path, size, key)
                        config_found = True

        # The config file hasn't been found/decrypted so fall back to hardcoded config
        if config_found == False:
            config_rva = struct.unpack("I", filebuf[yara_offset + 31 : yara_offset + 35])[0] - image_base
            config_offset = pe.get_offset_from_rva(config_rva)
            config = filebuf[config_offset : config_offset + size]

        c2_address = str(config[16 : 16 + MAX_IP_STRING_SIZE])
        if c2_address == "":
            return
        self.reporter.add_metadata("c2_address", c2_address)

        missionid = unicode_string_from_offset(config, 0x628, 128)
        if missionid:
            try:
                missionid.decode("ascii")
                self.reporter.add_metadata("missionid", missionid)
            except:
                pass
        return
