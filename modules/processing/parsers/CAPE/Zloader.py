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

DESCRIPTION = "Zloader configuration parser"
AUTHOR = "kevoreilly"

import logging
import struct

import pefile
import yara
from Cryptodome.Cipher import ARC4

log = logging.getLogger(__name__)

rule_source = """
rule Zloader
{
    meta:
        author = "kevoreilly, enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
        $decrypt_conf = {e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ??}
        $decrypt_conf_1 = {48 8d [5] [0-6] e8 [4] 48 [3-4] 48 [3-4] 48 [6] E8}
        $decrypt_key_1 = {66 89 C2 4? 8D 0D [3] 00 4? B? FC 03 00 00 E8 [4] 4? 83 C4}
    condition:
        uint16(0) == 0x5A4D and any of them
}
"""
MAX_STRING_SIZE = 32

yara_rules = yara.compile(source=rule_source)


def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


def extract_config(filebuf):
    end_config = {}
    pe = pefile.PE(data=filebuf, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    matches = yara_rules.match(data=filebuf)
    if not matches:
        return
    conf_type = ""
    decrypt_key = ""
    for match in matches:
        if match.rule != "Zloader":
            continue
        for item in match.strings:
            if "$decrypt_conf" == item.identifier:
                decrypt_conf = item.instances[0].offset + 21
                conf_type = "1"
            elif "$decrypt_conf_1" == item.identifier:
                decrypt_conf = item.instances[0].offset
                cva = 3
                conf_type = "2"
            elif "$decrypt_key_1" == item.identifier:
                decrypt_key = item.instances[0].offset
                size_s = 12
                kva_s = 6

    if conf_type == "1":
        va = struct.unpack("I", filebuf[decrypt_conf : decrypt_conf + 4])[0]
        key = string_from_offset(filebuf, pe.get_offset_from_rva(va - image_base))
        data_offset = pe.get_offset_from_rva(struct.unpack("I", filebuf[decrypt_conf + 5 : decrypt_conf + 9])[0] - image_base)
        enc_data = filebuf[data_offset:].split(b"\0\0", 1)[0]
        raw = decrypt_rc4(key, enc_data)
        items = list(filter(None, raw.split(b"\x00\x00")))
        end_config["Botnet name"] = items[1].lstrip(b"\x00")
        end_config["Campaign ID"] = items[2]
        for item in items:
            item = item.lstrip(b"\x00")
            if item.startswith(b"http"):
                end_config.setdefault("address", []).append(item)
            elif len(item) == 16:
                end_config["RC4 key"] = item
    elif conf_type == "2" and decrypt_key:
        conf_va = struct.unpack("I", filebuf[decrypt_conf + cva : decrypt_conf + cva + 4])[0]
        conf_offset = pe.get_offset_from_rva(conf_va + pe.get_rva_from_offset(decrypt_conf) + cva + 4)
        conf_size = struct.unpack("I", filebuf[decrypt_key + size_s : decrypt_key + size_s + 4])[0]
        key_va = struct.unpack("I", filebuf[decrypt_key + kva_s : decrypt_key + kva_s + 4])[0]
        key_offset = pe.get_offset_from_rva(key_va + pe.get_rva_from_offset(decrypt_key) + kva_s + 4)
        key = string_from_offset(filebuf, key_offset)
        conf_data = filebuf[conf_offset : conf_offset + conf_size]
        raw = decrypt_rc4(key, conf_data)
        items = list(filter(None, raw.split(b"\x00\x00")))
        end_config["Botnet name"] = items[0].decode("utf-8")
        end_config["Campaign ID"] = items[1].decode("utf-8")
        for item in items:
            item = item.lstrip(b"\x00")
            if item.startswith(b"http"):
                end_config.setdefault("address", []).append(item.decode("utf-8"))
            elif b"PUBLIC KEY" in item:
                end_config["Public key"] = item.decode("utf-8").replace("\n", "")

    return end_config


if __name__ == "__main__":
    import sys
    from pathlib import Path

    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
