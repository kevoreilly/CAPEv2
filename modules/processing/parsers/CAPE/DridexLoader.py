# Copyright (C) 2018 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
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

import socket
import struct
from contextlib import suppress

import pefile
import yara
from Cryptodome.Cipher import ARC4

DESCRIPTION = "DridexDropper configuration parser."
AUTHOR = "kevoreilly"

rule_source = """
rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexLoader Payload"

    strings:
        $c2parse_1 = {57 0F 95 C0 89 35 ?? ?? ?? ?? 88 46 04 33 FF 80 3D ?? ?? ?? ?? 00 76 54 8B 04 FD ?? ?? ?? ?? 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD ?? ?? ?? ?? 66 89 45 F0 8D 45 F8 50}
        $c2parse_2 = {89 45 00 0F B7 53 04 89 10 0F B6 4B 0C 83 F9 0A 7F 03 8A 53 0C 0F B6 53 0C 85 D2 7E B7 8D 74 24 0C C7 44 24 08 00 00 00 00 8D 04 7F 8D 8C 00}
        $c2parse_3 = {89 08 66 39 1D ?? ?? ?? ?? A1 ?? ?? ?? ?? 0F 95 C1 88 48 04 80 3D ?? ?? ?? ?? 0A 77 05 A0 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 56 8B F3 76 4E 66 8B 04 F5}
        $c2parse_4 = {0F B7 C0 89 01 A0 ?? ?? ?? ?? 3C 0A 77 ?? A0 ?? ?? ?? ?? A0 ?? ?? ?? ?? 57 33 FF 84 C0 74 ?? 56 BE}
        $c2parse_5 = {0F B7 05 [4] 89 02 89 15 [4] 0F B6 15 [4] 83 FA 0A 7F 07 0F B6 05 [4] 0F B6 05 [4] 85 C0}
        $c2parse_6 = {0F B7 53 ?? 89 10 0F B6 4B ?? 83 F9 0A 7F 03 8A 53 ?? 0F B6 53 ?? 85 D2 7E B9}
        $botnet_id = {C7 00 00 00 00 00 8D 00 6A 04 50 8D 4C ?? ?? E8 ?? ?? ?? ?? 0F B7 05}
        $rc4_key_1 = {56 52 BA [4] 8B F1 E8 [4] 8B C? 5? C3}
        $rc4_key_2 = {5? 8B ?9 52 [5-6] E8 [4] 8B C? 5? C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}
"""

MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0
LEN_BLOB_KEY = 40
LEN_BOT_KEY = 107

yara_rules = yara.compile(source=rule_source)


def decrypt_rc4(key, data):
    if not key:
        return b""
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def extract_rdata(pe):
    for section in pe.sections:
        if b".rdata" in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None


def extract_config(filebuf):
    cfg = {}
    pe = pefile.PE(data=filebuf, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    line, c2va_offset, delta = 0, 0, 0
    botnet_code, botnet_rva, rc4_decode = 0, 0, 0
    num_ips_rva = 0
    num_ips = 4

    matches = yara_rules.match(data=filebuf)
    if not matches:
        return

    for match in matches:
        if match.rule != "DridexLoader":
            continue
        for block in match.strings:
            for item in block.instances:
                if "$c2parse" in block.identifier:
                    c2va_offset = item.offset
                    line = block.identifier
                elif "$botnet_id" in block.identifier:
                    botnet_code = item.offset
                elif "$rc4_key" in block.identifier and not rc4_decode:
                    rc4_decode = item.offset
    if line == "$c2parse_6":
        c2_rva = struct.unpack("i", filebuf[c2va_offset + 44 : c2va_offset + 48])[0] - image_base
        botnet_rva = struct.unpack("i", filebuf[c2va_offset - 7 : c2va_offset - 3])[0] - image_base
        num_ips_rva = c2_rva - 1
    elif line == "$c2parse_5":
        c2_rva = struct.unpack("i", filebuf[c2va_offset + 75 : c2va_offset + 79])[0] - image_base
        botnet_rva = struct.unpack("i", filebuf[c2va_offset + 3 : c2va_offset + 7])[0] - image_base
        num_ips_rva = struct.unpack("i", filebuf[c2va_offset + 18 : c2va_offset + 22])[0] - image_base
    elif line == "$c2parse_4":
        c2_rva = struct.unpack("i", filebuf[c2va_offset + 6 : c2va_offset + 10])[0] - image_base + 1
    elif line == "$c2parse_3":
        c2_rva = struct.unpack("i", filebuf[c2va_offset + 60 : c2va_offset + 64])[0] - image_base
        delta = 2
    elif line == "$c2parse_2":
        c2_rva = struct.unpack("i", filebuf[c2va_offset + 47 : c2va_offset + 51])[0] - image_base
    elif line == "$c2parse_1":
        c2_rva = struct.unpack("i", filebuf[c2va_offset + 27 : c2va_offset + 31])[0] - image_base
        delta = 2
    else:
        return

    try:
        c2_offset = pe.get_offset_from_rva(c2_rva)
    except pefile.PEFormatError:
        return

    num_ips = 0
    if num_ips_rva:
        num_ips_offset = pe.get_offset_from_rva(num_ips_rva)
        ip_data = filebuf[num_ips_offset : num_ips_offset + 1]
        if ip_data:
            num_ips = struct.unpack("B", filebuf[num_ips_offset : num_ips_offset + 1])[0]

    for _ in range(num_ips):
        ip = struct.unpack(">I", filebuf[c2_offset : c2_offset + 4])[0]
        c2_address = socket.inet_ntoa(struct.pack("!L", ip))
        port = str(struct.unpack("H", filebuf[c2_offset + 4 : c2_offset + 6])[0])

        if c2_address and port:
            cfg.setdefault("address", []).append(f"{c2_address}:{port}")

        c2_offset += 6 + delta

    if rc4_decode:
        zb = struct.unpack("B", filebuf[rc4_decode + 8 : rc4_decode + 9])[0]
        if not zb:
            rc4_rva = struct.unpack("i", filebuf[rc4_decode + 5 : rc4_decode + 9])[0] - image_base
        else:
            rc4_rva = struct.unpack("i", filebuf[rc4_decode + 3 : rc4_decode + 7])[0] - image_base
        if rc4_rva:
            rc4_offset = pe.get_offset_from_rva(rc4_rva)
            if not zb:
                raw = decrypt_rc4(
                    filebuf[rc4_offset : rc4_offset + LEN_BLOB_KEY][::-1],
                    filebuf[rc4_offset + LEN_BLOB_KEY : rc4_offset + LEN_BOT_KEY],
                )
            else:
                raw = decrypt_rc4(
                    filebuf[rc4_offset : rc4_offset + LEN_BLOB_KEY], filebuf[rc4_offset + LEN_BLOB_KEY : rc4_offset + LEN_BOT_KEY]
                )
            for item in raw.split(b"\x00"):
                if len(item) == LEN_BLOB_KEY - 1:
                    cfg["RC4 key"] = item.split(b";", 1)[0].decode()

    if botnet_code:
        botnet_rva = struct.unpack("i", filebuf[botnet_code + 23 : botnet_code + 27])[0] - image_base
    if botnet_rva:
        with suppress(struct.error):
            botnet_offset = pe.get_offset_from_rva(botnet_rva)
            botnet_id = struct.unpack("H", filebuf[botnet_offset : botnet_offset + 2])[0]
            cfg["Botnet ID"] = str(botnet_id)

    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
