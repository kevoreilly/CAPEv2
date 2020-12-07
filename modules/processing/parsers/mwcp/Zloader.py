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

    def run(self):
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
                
        botnet_id, campaign_id = list(filter(None, raw[1:41].split(b'\x00') ))
        controllers = list(filter(None, raw[41:696].split(b'\x00') ))
        rc4_key = raw[696: 696 + raw[696:].find(b'\x00') ]

        self.reporter.add_metadata("other", {"Botnet name": botnet_id})
        self.reporter.add_metadata("other", {"Campaign ID": campaign_id})
        for controller in controllers:
            self.reporter.add_metadata("address", controller)

        self.reporter.add_metadata("other", {"RC4 key": rc4_key})
        return
