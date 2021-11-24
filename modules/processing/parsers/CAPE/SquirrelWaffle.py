# Copyright (C) 2021 Kevin O'Reilly (kevoreilly@gmail.com)
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
import struct
import pefile
import yara
from itertools import cycle

rule_source = """
rule SquirrelWaffle
{
    strings:
        $config = {83 C2 04 83 C1 04 83 EE 04 73 EF 83 FE FC 74 34 8A 02 3A 01 75 27 83 FE FD 74 29 8A 42 01 3A 41 01 75 1A 83 FE FE 74 1C 8A 42 02 3A 41 02 75 0D}
        $decode = {F7 75 ?? 83 7D ?? 10 8D 4D ?? 8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39}
        $c2key = {83 EC 18 8B CC 89 A5 [4] 6A 05 C7 41 ?? 00 00 00 00 C7 41 ?? 0F 00 00 00 68}
    condition:
        uint16(0) == 0x5A4D and any of them
}
"""

yara_rules = yara.compile(source=rule_source)

MAX_STRING_SIZE = 32

def string_from_offset(data, offset):
    string = data[offset : offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string

def extract_rdata(pe):
    for section in pe.sections:
        if b'.rdata' in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None

def xor_data(data, key):
    key = [q for q in key]
    data = [q for q in data]
    return bytes([c ^ k for c, k in zip(data, cycle(key))])

def config(data):
    config = dict()
    pe = None
    try:
        pe = pefile.PE(data=data)
    except Exception as e:
        return config

    if pe != None:
        rdata = extract_rdata(pe)
        if len(rdata) == 0:
            return config
        chunks = [x for x in rdata.split(b'\x00') if x != b'']
        for i in range(len(chunks)):
            if len(chunks[i]) > 100:
                try:
                    decrypted = xor_data(chunks[i], chunks[i+1]).decode("utf-8")
                    if '\r\n' in decrypted and '|' not in decrypted:
                        config["IP Blocklist"] = list(filter(None, decrypted.split("\r\n")))
                    elif '|' in decrypted and '.' in decrypted and '\r\n' not in decrypted:
                        config["URLs"] = list(filter(None, decrypted.split("|")))
                except:
                    continue
        matches = yara_rules.match(data=data)
        if not matches:
            return config
        for match in matches:
            if match.rule != "SquirrelWaffle":
                continue
            for item in match.strings:
                if '$c2key' in item[1]:
                    c2key_offset = int(item[0])
                    key_rva = struct.unpack("i", data[c2key_offset + 28 : c2key_offset + 32])[0] - pe.OPTIONAL_HEADER.ImageBase
                    key_offset = pe.get_offset_from_rva(key_rva)
                    config["C2 key"] = string_from_offset(data, key_offset).decode("utf-8")
                    return config
