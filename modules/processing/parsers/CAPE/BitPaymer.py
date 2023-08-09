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

DESCRIPTION = "BitPaymer configuration parser."
AUTHOR = "kevoreilly"

import string

import pefile
import yara
from Cryptodome.Cipher import ARC4

rule_source = """
rule BitPaymer
{
    meta:
        author = "kevoreilly"
        description = "BitPaymer Payload"
        cape_type = "BitPaymer Payload"

    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $antidefender = "TouchMeNot" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
"""

LEN_BLOB_KEY = 40


def convert_char(c):
    if c in (string.letters + string.digits + string.punctuation + " \t\r\n"):
        # ToDo gonna break as its int
        return c
    return f"\\x{ord(c):02x}"


def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def yara_scan(raw_data, rule_name):
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule != "BitPaymer":
            continue

        for block in match.strings:
            for instance in block.instances:
                if block.identifier == rule_name:
                    return {block.identifier: instance.offset}


def extract_rdata(pe):
    for section in pe.sections:
        if ".rdata" in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None


def extract_config(file_data):
    pe = pefile.PE(data=file_data, fast_load=False)
    config = {}
    blobs = filter(None, [x.strip(b"\x00\x00\x00\x00") for x in extract_rdata(pe).split(b"\x00\x00\x00\x00")])
    for blob in blobs:
        if len(blob) < LEN_BLOB_KEY:
            continue
        raw = decrypt_rc4(blob[:LEN_BLOB_KEY][::-1], blob[LEN_BLOB_KEY:])
        if not raw:
            continue
        for item in raw.split(b"\x00"):
            data = "".join(convert_char(c) for c in item)
            if len(data) == 760:
                config["RSA public key"] = data
            elif len(data) > 1 and "\\x" not in data:
                config["strings"] = data
    return config
