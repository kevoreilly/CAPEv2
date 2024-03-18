# Copyright (C) 2024 enzok
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


import logging
import re
from contextlib import suppress

import pefile
import yara

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

rule_source = """
rule Carbanak
{
    meta:
        author = "enzok"
        description = "Carbanak sbox constants"
        cape_type = "Carbanak Payload"
    strings:
        $constants = {0F B7 05 [3] 00 0F B7 1D [3] 00 83 25 [3] 00 00 89 05 [3] 00 0F B7 05 [3] 00 89 1D [3] 00 89 05 [3] 00 33 C0 4? 8D 4D}    
    condition:
        all of them
}
"""

yara_rules = yara.compile(source=rule_source)

const_a = 0
const_b = 0
const_c = 0


def decode_string(src, sbox):
    lenstr = len(src) - 4
    if lenstr < 0:
        lenstr = 0
    newstr = bytearray()
    lenblock = int(lenstr / 4)
    nb = 0
    rb = 0
    delta = 0
    n = 0
    i = 0
    while n < lenstr:
        if rb == 0:
            nb += 1
            if nb <= 4:
                delta = src[i] - 97
                i += 1
                rb = lenblock
            else:
                rb = lenstr - n
        elif rb > 0:
            rb -= 1
            c = src[i]
            if c < 32:
                min = 1
                max = 31
            elif c < 128:
                min = 32
                max = 127
            else:
                min = 128
                max = 255
            c = sbox[c]
            c -= delta
            if c < min:
                c = max - min + c
            n += 1
            newstr.append(c)
            i += 1
    return newstr


def scramble(sbox, start, end, count):
    global const_a
    length = end - start + 1
    while count > 0:
        s1 = (const_c + const_a * const_b) & 0xFFFF
        const_a = (const_c + s1 * const_b) & 0xFFFF
        i = start + s1 % length
        s3 = sbox[i]
        j = start + const_a % length
        sbox[i] = sbox[j]
        sbox[j] = s3
        count -= 1
    return sbox


def extract_config(filebuf):
    global const_a, const_b, const_c
    cfg = {}
    constants_offset = None
    pe = pefile.PE(data=filebuf)
    matches = yara_rules.match(data=filebuf)
    if not matches:
        return

    for match in matches:
        if match.rule != "Carbanak":
            continue
        for item in match.strings:
            for instance in item.instances:
                if "$constants" in item.identifier:
                    constants_offset = int(instance.offset)

    if not constants_offset:
        return

    data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
    text_sections = [s for s in pe.sections if s.Name.find(b".text") != -1]

    if not data_sections or not text_sections:
        return None

    text_start = text_sections[0].PointerToRawData
    rva = constants_offset - text_start + text_sections[0].VirtualAddress
    const_b_offset = pe.get_dword_from_offset(constants_offset + 3)
    const_b_rva = rva + const_b_offset + 7
    const_b_offset = const_b_rva - data_sections[0].VirtualAddress + data_sections[0].PointerToRawData
    const_b = pe.get_word_from_offset(const_b_offset)
    const_a = pe.get_word_from_offset(const_b_offset - 2)
    const_c = pe.get_word_from_offset(const_b_offset + 2)

    # init sbox
    sbox_init = bytearray(range(256))
    count = const_a % 1000 + 128
    sbox_init = scramble(sbox_init, 1, 31, count)
    sbox_init = scramble(sbox_init, 32, 127, count)
    sbox_init = scramble(sbox_init, 128, 255, count)
    sbox = bytearray(256)
    for idx, dst in enumerate(sbox_init):
        sbox[dst] = idx

    rdata_sections = [s for s in pe.sections if s.Name.find(b".rdata") != -1]
    if rdata_sections:
        rdata = rdata_sections[0].get_data()
        items = rdata.split(b"\x00")
        items = [item for item in items if item != b""]
        for item in items:
            with suppress(IndexError, UnicodeDecodeError, ValueError):
                dec = decode_string(item, sbox).decode("utf8")
                if dec:
                    ver = re.findall("^(\d+\.\d+)$", dec)
                    if ver:
                        cfg["Version"] = ver[0]

    data = data_sections[0].get_data()
    items = data.split(b"\x00")

    with suppress(IndexError, UnicodeDecodeError, ValueError):
        cfg["Unknown 1"] = decode_string(items[0], sbox).decode("utf8")
        cfg["Unknown 2"] = decode_string(items[8], sbox).decode("utf8")
        c2_dec = decode_string(items[10], sbox).decode("utf8")
        if "|" in c2_dec:
            c2_dec = c2_dec.split("|")
        cfg["C2"] = c2_dec
        if float(cfg["Version"]) < 1.7:
            cfg["Campaign Id"] = decode_string(items[276], sbox).decode("utf8")
        else:
            cfg["Campaign Id"] = decode_string(items[25], sbox).decode("utf8")

    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
