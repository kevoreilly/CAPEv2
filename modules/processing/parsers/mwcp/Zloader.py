# Copyright (C) 2020 Kevin O'Reilly (kevoreilly@gmail.com)
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
import string
import pefile
import yara
import re
from Crypto.Cipher import ARC4

rule_source = '''
rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
        $decrypt_conf = {83 C4 04 84 C0 74 54 E8 [4] E8 [4] E8 [4] E8 [4] 68 [4] 68 [4] E8}
    condition:
        uint16(0) == 0x5A4D and any of them
}

'''
MAX_STRING_SIZE = 32

def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'Zloader':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses

def string_from_offset(data, offset):
    string = data[offset : offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string

class Zloader(Parser):

    DESCRIPTION = 'Zloader configuration parser'
    AUTHOR = 'kevoreilly'

    def get_config(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        hit = yara_scan(filebuf, "$decrypt_conf")
        if not hit:
            return
        decrypt_conf = int(hit["$decrypt_conf"])
        key = string_from_offset(filebuf, pe.get_offset_from_rva(struct.unpack("I",filebuf[decrypt_conf+28:decrypt_conf+32])[0]-image_base))
        data_offset = pe.get_offset_from_rva(struct.unpack("I",filebuf[decrypt_conf+33:decrypt_conf+37])[0]-image_base)
        enc_data = filebuf[data_offset:].split(b"\0\0")[0]
        raw = decrypt_rc4(key, enc_data)
        items = list(filter(None, raw.split(b'\x00\x00')))
        self.reporter.add_metadata("other", {"Version": str(ord(items[0]))})
        self.reporter.add_metadata("other", {"Botnet name": items[1]})
        self.reporter.add_metadata("other", {"Campaign ID": items[2]})
        for item in items:
            item = item.lstrip(b'\x00')
            if len(item) == 128:
                self.reporter.add_metadata("other", {"RSA key": item.hex()})
            elif item.startswith(b'http'):
                self.reporter.add_metadata("address", item)
            elif len(item) == 16:
                self.reporter.add_metadata("other", {"RC4 key": item})
        return
