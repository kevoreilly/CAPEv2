# Copyright (C) 2017-2021 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
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
import socket
import struct
from contextlib import suppress
from itertools import cycle
from pathlib import Path

import pefile
import yara
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Util import asn1

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

try:
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, Uc, UcError
    from unicorn.x86_const import UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSP
except ImportError:
    log.error("Unicorn not installed")

AUTHOR = "kevoreilly"

rule_source = """
rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"
    strings:
        $snippet1 = {FF 15 [4] 83 C4 0C 68 40 00 00 F0 6A 18}
        $snippet3 = {83 3D [4] 00 C7 05 [8] C7 05 [8] 74 0A 51 E8 [4] 83 C4 04 C3 33 C0 C3}
        $snippet4 = {33 C0 C7 05 [8] C7 05 [8] A3 [4] A3 [19] 00 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 83 C4 04 C3}
        $snippet5 = {8B E5 5D C3 B8 [4] A3 [4] A3 [4] 33 C0 21 05 [4] A3 [4] 39 05 [4] 74 18 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 59 C3}
        $snippet6 = {33 C0 21 05 [4] A3 [4] 39 05 [4] 74 18 40 A3 [4] 83 3C C5 [4] 00 75 F0 51 E8 [4] 59 C3}
        $snippet7 = {8B 48 ?? C7 [5-6] C7 40 [4] ?? C7 [2] 00 00 00 [0-1] 83 3C CD [4] 00 74 0E 41 89 48 ?? 83 3C CD [4] 00 75 F2}
        $snippet8 = {85 C0 74 3? B9 [2] 40 00 33 D2 89 ?8 [0-1] 89 [1-2] 8B [1-2] 89 [1-2] EB 0? 41 89 [1-2] 39 14 CD [2] 40 00 75 F? 8B CE E8 [4] 85 C0 74 05 33 C0 40 5E C3}
        $snippet9 = {85 C0 74 4? 8B ?8 [0-1] C7 40 [5] C7 [5-6] C7 40 ?? 00 00 00 00 83 3C CD [4] 00 74 0? 41 89 [2-3] 3C CD [4] 00 75 F? 8B CF E8 [4] 85 C0 74 07 B8 01 00 00 00 5F C3}
        $snippetA = {85 C0 74 5? 8B ?8 04 89 78 28 89 38 89 70 2C EB 04 41 89 48 04 39 34 CD [4] 75 F3 FF 75 DC FF 75 F0 8B 55 F8 FF 75 10 8B 4D EC E8 [4] 83 C4 0C 85 C0 74 05}
        $snippetB = {EB 04 4? 89 [2] 39 [6] 75 F3}
        $snippetC = {EB 03 4? 89 1? 39 [6] 75 F4}
        $snippetD = {8D 44 [2] 50 68 [4] FF 74 [2] FF 74 [2] 8B 54 [2] 8B 4C [2] E8}
        $snippetE = {FF 74 [2] 8D 54 [2] FF 74 [2] 68 [4] FF 74 [2] 8B 4C [2] E8 [4] 8B 54 [2] 83 C4 10 89 44 [2] 8B F8 03 44 [2] B9 [4] 89 44 [2] E9 [2] FF FF}
        $snippetF = {FF 74 [2] 8D 44 [2] BA [4] FF 74 [2] 8B 4C [2] 50 E8 [4] 8B 54 [2] 8B D8 8B 84 [5] 83 C4 0C 03 C3 89 5C [2] 8B FB 89 44}
        $snippetG = {FF 74 [2] 8B 54 [2] 8D 44 [2] 8B 4C [2] 50 E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 89 44}
        $snippetH = {FF 74 [2] 8D 84 [5] 68 [4] 50 FF 74 [2] 8B 54 [2] 8B 4C [2] E8 [4] 8B 94 [5] 83 C4 10 89 84 [5] 8B F8 03 84}
        $snippetI = {FF 74 [2] 8D 8C [5] FF 74 [2] 8B 54 [2] E8 [4] 8B 54 [2] 8B D8 8B 84 [5] 83 C4 0C 03 C3 89 5C [2] 8B FB 89 44 24 74}
        $snippetJ = {FF 74 [2] 8B 4C [2] 8D 44 [2] 50 BA [4] E8 [4] 8B 54 [2] 8B F8 59 89 44 [2] 03 44 [2] 59 89 44 [2] B9 [4] E9}
        $snippetK = {FF 74 [2] FF 74 [2] 8B 54 [2] E8 [4] 8B 54 [2] 83 C4 0C 89 44 [2] 8B F8 03 44 [2] B9 [4] 89 44 [2] E9}
        $snippetL = {FF 74 [2] 8B 54 [2] 8D 4C [2] E8 [4] 59 89 44 [2] 8B F8 03 44 [2] 59 89 44 24 68 B9 [4] E9}
        $snippetM = {FF 74 [2] 8D 84 [3] 00 00 B9 [4] 50 FF 74 [2] FF 74 [2] 8B 94 [3] 00 00 E8 [4] 83 C4 10 89 44 [2] 8B F8 B9 [4] 03 84 [3] 00 00 89 44 [2] E9}
        $snippetN = {FF 74 [2] 8D 44 [2] B9 [4] FF 74 [2] 50 FF 74 [2] 8B 54 [2] E8 [4] 8B 8C [3] 00 00 83 C4 10 03 C8 89 44 [2] 89 4C [2] 8B F8 B9 45 89 77 05 E9}
        $snippetO = {8D 44 [2] B9 [4] 50 FF 74 [2] 8B 54 [2] E8 [4] 8B D0 8B 44 [2] 59 59 03 C2 89 54 [2] 8B FA 89 44 [2] B9 [4] E9}
        $snippetP = {FF 74 [2] 8B 54 [2] 8D 44 [2] 8B 4C [2] 68 [4] 50 E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 8B 54 [2] B9 [4] 89 44 [2] E9}
        $snippetQ = {FF 74 [2] BA [4] 8D 4C [2] FF 74 [2] E8 [4] 59 89 84 [3] 00 00 8B F8 03 44 [2] 59 89 44 [2] B9 [4] 81 F9 [4] 74 28 8B 54 [2] E9}
        $snippetR = {8D 44 [2] 50 FF 74 [2] 8B 54 [2] 8B 4C [2] 68 [4] E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 8B 54 [2] B9 [4] 89 44 [2] E9}
        $snippetS = {FF 74 [2] 8D 54 [2] FF 74 [2] 8B 4C [2] E8 [4] 8B D0 83 C4 0C 8B 44 [2] 8B FA 03 C2 89 54 [2] 8B 54 [2] B9 [4] 89 44 [2] E9}
        $snippetT = {8B 54 [2] 8D 44 [2] 8B 4C [2] 68 [4] 50 E8 [4] 8B 9C [3] 00 00 8B F8 59 59 03 D8 89 44 [2] 89 5C [2] B9 [4] EB}
        $snippetU = {89 44 [2] 33 D2 8B 44 [2] F7 F1 B9 [4] 89 44 [2] 8D 44 [2] 81 74 [6] C7 44 [6] 81 44 [6] 81 74 [6] FF 74 [2] 50 FF 74 [2] FF 74 [2] 8B 54 [2] E8}
        $snippetV = {81 74 [2] ED BC 9C 00 FF 74 [2] 50 68 [4] FF 74 [2] 8B 54 [2] 8B 4C [2] E8}
        $snippetW = {4C 8D [2] 8B [2] 4C 8D 05 [4] F7 E1 2B CA D1 E9 03 CA C1 E9 06 89}
        $snippetX = {4C 8D 0? [2] (00|01) 00 [0-80] 48 8D [0-9] 81 75 [5] C7 45 [5-14] 81}
        $snippetY = {(3D [4] 0F 84 [4] 3D [4] 0F 85 [3] ??|B8 [4] E9 [3] ??) 48 8D 05 [4] 48 89 (81 [3] ??|41 ??) 48 8D 05 [4] 48 89 (81 [3] ??|41 ??) 48 8D 05 [4] 48 89}
        $snippetZ = {(48 8B D8 48 85 C0 0F 84 [4-9] E9 [4-190] ?? | 55 53 48 8D AC 24 [2] FF FF 48 81 EC [2] 00 00 48 8B [3] 00 00 [0-80] ??) 48 8D 05 [4] 48 89 (85 [3] ??|4? ??) [0-220] 48 8D 05 [4] 48 89 (85 [3] ??|4? ??) [0-220] 48 8D 05 [4] 48 89 (85 [3] ??|4? ??)}
        $comboA1 = {83 EC 28 56 FF 75 ?? BE}
        $comboA2 = {83 EC 38 56 57 BE}
        $comboA3 = {EB 04 40 89 4? ?? 83 3C C? 00 75 F6}
        $ref_rsa = {6A 00 6A 01 FF [4-9] C0 [5-11] E8 ?? ?? FF FF 8D 4? [1-2] B9 ?? ?? ?? 00 8D 5? [4-6] E8}
        $ref_ecc1 = {8D 84 [5] 50 68 [4] FF B4 24 [4] FF B4 24 [4] 8B 94 24 [4] 8B 8C 24 [4] E8 [4] 89 84 24 [4] 8D 84 24 [4] 50 68 [4] FF B4 24 [4] FF B4 24 [4] 8B 54 24 40 8B 8C 24 [4] E8}
        $ref_ecc2 = {FF B4 [3] 00 00 8D 94 [3] 00 00 FF B4 [3] 00 00 68 [4] FF 74 [2] 8B 8C [3] 00 00 E8 [4] FF B4 [3] 00 00 8D 94 [3] 00 00 89 84 [3] 00 00 FF B4 [3] 00 00 68 [4] FF 74 [2] 8B 8C [3] 00 00 E8}
        $ref_ecc3 = {8D 84 [5] BA [4] FF B4 [5] 8B 4C [2] 50 E8 [4] 83 C4 0C 89 84 [5] 8D 84 [5] BA [4] FF B4 [5] FF B4 [5] 8B 8C [5] 50 E8 05 05 01 00}
        $ref_ecc4 = {FF 74 [2] 8B 94 [5] 8D 84 [5] 8B 8C [5] 50 E8 [4] 83 C4 0C 89 84 [5] 8D 84 [5] 68 [4] FF B4 [5] 8B 54 [2] 8B 8C [5] 50 E8}
        $ref_ecc5 = {FF B4 [3] 00 00 8D 84 [3] 00 00 68 [4] 50 FF B4 [3] 00 00 8B 94 [3] 00 00 8B 4C [2] E8 [4] FF B4 [3] 00 00 89 84 [3] 00 00 8D 84}
        $ref_ecc6 = {FF B4 [3] 00 00 8D 8C [3] 00 00 FF B4 [3] 00 00 8B 54 [2] E8 [4] 83 C4 0C 89 84 [5] 8D 8C [5] 68 [4] FF B4 [5] FF 74 [2] 8B 94 24 [4] E8}
        $ref_ecc7 = {FF B4 [3] 00 00 8B 8C [3] 00 00 8D 84 [3] 00 00 50 BA [4] E8 [4] FF B4 [3] 00 00 8B 8C [3] 00 00 BA [4] 89 84 [3] 00 00 8D 84 [3] 00 00 50 E8}
        $ref_ecc8 = {FF B4 [3] 00 00 FF B4 [3] 00 00 8B 94 [3] 00 00 E8 [4] 83 C4 0C 89 84 [3] 00 00 8D 84 [3] 00 00 B9 [4] 50 FF B4 [3]00 00 FF B4 [3]00 00 8B 94 [3]00 00 E8}
        $ref_ecc9 = {FF B4 [3] 00 00 8B 54 [2] 8D 8C [3] 00 00 E8 [4] 68 [4] FF B4 [3] 00 00 8B 94 [3] 00 00 8D 8C [3] 00 00 89 84 [3] 00 00 E8}
        $ref_eccA = {FF 74 [2] 8D 84 [3] 00 00 B9 [4] 50 FF 74 [2] FF B4 [3] 00 00 8B 94 [3] 00 00 E8 [4] FF B4 [3] 00 00 89 84 [3] 00 00 B9 [4] 8D 84 [3] 00 00 50}
        $ref_eccB = {FF B4 [3] 00 00 8D 84 [3] 00 00 B9 [4] FF 74 [2] 50 FF B4 [3] 00 00 8B 94 [3] 00 00 E8 [4] FF B4 [3] 00 00 89 84 [3] 00 00 B9}
        $ref_eccC = {8D 84 [3] 00 00 B9 [4] 50 FF 74 [2] 8B 94 [3] 00 00 E8 [4] 89 84 [3] 00 00 B9 [4] 8D 84 [3] 00 00 50 FF B4 [3] 00 00 8B 94 [3] 00 00 E8}
        $ref_eccD = {FF B4 [3] 00 00 8B 54 [2] 8D 84 [3] 00 00 8B 8C [3] 00 00 68 [4] 50 E8 [4] 83 C4 0C 89 84 [3] 00 00 8D 84 [3] 00 00 FF B4 [3] 00 00 8B 94 [3] 00 00 8B 4C [2] 68 [4] 50 E8}
        $ref_eccE = {FF B4 [3] 00 00 BA [4] 8D 8C [3] 00 00 FF B4 [3] 00 00 E8 [4] FF 74 [2] BA [4] 89 84 [3] 00 00 FF 74 [2] 8D 8C [3] 00 00 E8}
        $ref_eccF = {FF B4 [3] 00 00 8D 94 [3] 00 00 FF B4 [3] 00 00 8B 4C [2] E8 [4] 83 C4 0C 89 84 [3] 00 00 8D 94 [3] 00 00 68 [4] FF 74 [2] FF B4 [3] 00 00 8B 4C [2] E8}
        $ref_eccG = {8D 84 [3] 00 00 50 FF B4 [3] 00 00 8B 94 [3] 00 00 8B 8C [3] 00 00 68 [4] E8 [4] 83 C4 0C 89 84 [3] 00 00 8D 84 [3] 00 00 50 FF 74 [2] 8B 94 [3] 00 00 8B 8C [3] 00 00 68 [4] E8}
        $ref_eccH = {8D 84 [5] 50 68 [4] FF 74 [2] FF B4 [3] 00 00 8B 94 [3] 00 00 8B 8C [3] 00 00 E8 [4] 89 84 [3] 00 00 8D 84 [3] 00 00 50 68}
        $ref_eccI = {8B 94 [3] 00 00 8D 84 [3] 00 00 8B 8C [3] 00 00 68 [4] 50 E8 [4] 8B 54 [2] 8B 8C [3] 00 00 89 84 [3] 00 00 8D 84 [3] 00 00 68 [4] 50 E8}
        $ref_eccJ = {8B 44 [2] 6A 6D 59 F7 F1 B9 [4] 89 44 [2] 8D 44 [2] 81 74 [6] C7 44 [6] C1 64 [3] C1 6C [3] 81 74 [6] C7 44 [6] 81 44 [6] 81 4C [6] 81 74 [6] FF 74 [2] 50 FF 74 [2] FF 74 [2] 8B 54 [2] E8}
        $ref_eccK = {81 74 [2] 82 8D 0C 00 FF 74 [2] 50 68 [4] FF 74 [2] 8B 54 [2] 8B 4C [2] E8}
        $ref_eccL = {4C 8D [3] 4C 8D [5] 81 85 ?? 00 00 00 [4] 81 B5 ?? 00 00 00 [4] C7 85 ?? 00 00 00}
        $ref_eccM = {4C 8D 0D [4] 81 B5 ?? 00 00 00 [4] 81 B5 ?? 00 00 00 [4] C7 85 ?? 00 00 00 [4] 81 B5 ?? 00 00 00 [4] 6B 85}
        $ref_eccN = {4C 8D 05 [4-28] F7 E1 2B CA D1 E9 03 CA C1 E9 05 89 8D ?? 00 00 00 C1 AD ?? 00 00 00 ?? 81 B5 ?? 00 00 00}
        $ref_eccO = {4C 8D 0D [4] 8B 45 ?? 8D 0C ?? B8 [4] 03 C9 89 4D ?? 8B 4D ?? F7 E1 B8 [4] 2B CA D1 E9 03 CA C1 E9 05}
        $ref_eccP = {40 55 48 8D 6C 24 ?? 48 81 EC [12-36] C7 45 [4] 00 [0-60] C7 45 [4] 00 [0-60] C7 45 [4] 00 [0-60] C7 45}
    condition:
        uint16(0) == 0x5A4D and any of ($snippet*) or 2 of ($comboA*) or $ref_rsa or any of ($ref_ecc*)
}
"""

MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0


def first_match(matches, pattern):
    if not matches:
        return 0
    for item in matches[0].strings:
        if pattern == item.identifier:
            return item.instances[0].offset
    return 0


def addresses_from_matches(matches, pattern):
    addresses = []
    for match in matches:
        for item in match.strings:
            if item.identifier == pattern:
                addresses.append(item.instances[0].offset)
    return addresses


def c2_funcs_from_match(matches, pattern, data):
    addresses = []
    addr = first_match(matches, pattern)
    hit = addr + data[addr:].find(b"\x48\x8D\x05")
    next = 1
    while next > 0:
        addresses.append(struct.unpack("i", data[hit + 3 : hit + 7])[0] + hit + 7)
        next = data[hit + 7 : hit + 600].find(b"\x48\x8D\x05")
        if next != -1:
            hit += next + 7
    return addresses


def xor_data(data, key):
    return bytes(c ^ k for c, k in zip(data, cycle(key)))


def emotet_decode(data, size, xor_key):
    offset = 8
    res = b""
    for count in range(int(size / 4)):
        off_from = offset + count * 4
        off_to = off_from + 4
        encoded_dw = int.from_bytes(data[off_from:off_to], byteorder="little")
        decoded = xor_key ^ encoded_dw
        res += decoded.to_bytes(4, byteorder="little")
    return res


# Thanks to Jason Reaves (@sysopfb), @pollo290987, phate1.
def extract_emotet_rsakey(pe):
    for section in pe.sections:
        if section.Name.replace(b"\x00", b"") == b".data":
            data_section = section.get_data()
            data_size = len(data_section)
    res_list = []
    if data_size:
        delta = 0
        while delta < data_size:
            xor_key = int.from_bytes(data_section[delta : delta + 4], byteorder="little")
            encoded_size = int.from_bytes(data_section[delta + 4 : delta + 8], byteorder="little")
            decoded_size = ((xor_key ^ encoded_size) & 0xFFFFFFFC) + 4
            if decoded_size == 0x6C:
                res_list.append(emotet_decode(data_section[delta:], decoded_size, xor_key))
                break
            delta += 4
        if res_list:
            res_list = list(set(res_list))
            pub_key = res_list[0][:106]
            seq = asn1.DerSequence()
            try:
                seq.decode(pub_key)
            except Exception as e:
                logging.exception(e)
                return
            return RSA.construct((seq[0], seq[1]))
    for section in pe.sections:
        if section.Name.replace(b"\x00", b"") == b".text":
            code_section = section.get_data()
            code_size = len(code_section)
    if code_size:
        delta = 0
        while delta < code_size:
            xor_key = int.from_bytes(code_section[delta : delta + 4], byteorder="little")
            encoded_size = int.from_bytes(code_section[delta + 4 : delta + 8], byteorder="little")
            decoded_size = ((xor_key ^ encoded_size) & 0xFFFFFFFC) + 4
            if decoded_size == 0x6C:
                res_list.append(emotet_decode(code_section[delta:], decoded_size, xor_key))
                break
            delta += 4
        if res_list:
            res_list = list(set(res_list))
            pub_key = res_list[0][:106]
            seq = asn1.DerSequence()
            try:
                seq.decode(pub_key)
            except ValueError:
                # log.error(e)
                return
            return RSA.construct((seq[0], seq[1]))


stack = 0x80000
code_base = 0x180001000


def hook_instr(uc, address, size, mode):
    global call_count
    ins = uc.mem_read(address + size, 1)
    if ins == (b"\xe8"):
        call_count = call_count + 1
    if call_count == 4:
        call_count = 0
        uc.reg_write(UC_X86_REG_RAX, stack + 0x400)
        uc.reg_write(UC_X86_REG_RIP, uc.reg_read(UC_X86_REG_RIP) + 9)
    return True


def emulate(code, ep):
    global call_count
    call_count = 0
    with suppress(UcError):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        size = int(len(code) / 0x1000) * 0x1000
        if len(code) % 0x1000:
            size = size + 0x1000
        uc.mem_map(code_base, size)
        uc.mem_write(code_base, code)
        uc.mem_map(stack, 0x1000)
        uc.mem_map(0x0, 0x1000)
        uc.reg_write(UC_X86_REG_RSP, stack + 0x200)
        uc.reg_write(UC_X86_REG_RCX, stack + 0x104)
        uc.reg_write(UC_X86_REG_RDX, stack + 0x108)
        uc.reg_write(UC_X86_REG_R9, stack + 0x108)
        uc.hook_add(UC_HOOK_CODE, hook_instr, user_data=UC_MODE_64)
        uc.emu_start(code_base + ep, code_base + len(code))
    return uc


def extract_config(filebuf):
    conf_dict = {}
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=filebuf, fast_load=False)
        code = filebuf[pe.sections[0].PointerToRawData : pe.sections[0].PointerToRawData + pe.sections[0].SizeOfRawData]

    if pe is None:
        return

    image_base = pe.OPTIONAL_HEADER.ImageBase
    c2found = False
    c2list_va_offset = 0
    c2_list_offset = 0
    delta = 0
    c2_funcs = []
    ecc_funcs = []

    yara_rules = yara.compile(source=rule_source)
    yara_matches = yara_rules.match(data=filebuf)

    if first_match(yara_matches, "$snippet3"):
        c2list_va_offset = first_match(yara_matches, "$snippet3")
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 2 : c2list_va_offset + 6])[0]
        c2_list_rva = c2_list_va & 0xFFFF if c2_list_va - image_base > 0x20000 else c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError:
            pass

        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except Exception:
                return
            if ip == 0:
                return
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if not c2_address or not port:
                return
            conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2_list_offset += 8
    elif first_match(yara_matches, "$snippet4"):
        c2list_va_offset = first_match(yara_matches, "$snippet4")
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 8 : c2list_va_offset + 12])[0]
        c2_list_rva = c2_list_va & 0xFFFF if c2_list_va - image_base > 0x20000 else c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError:
            pass
        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except Exception:
                return
            if ip == 0:
                return
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if not c2_address or not port:
                return
            conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2_list_offset += 8
    elif any(
        first_match(yara_matches, name)
        for name in ("$snippet5", "$snippet8", "$snippet9", "$snippetB", "$snippetC", "$comboA1", "$comboA2")
    ):
        delta = 5
        if first_match(yara_matches, "$snippet5"):
            refc2list = first_match(yara_matches, "$snippet5")
        elif first_match(yara_matches, "$snippet8"):
            refc2list = first_match(yara_matches, "$snippet8")
        elif first_match(yara_matches, "$snippet9"):
            refc2list = first_match(yara_matches, "$snippet8")
            c2list_va_offset = first_match(yara_matches, "$snippet9")
            tb = struct.unpack("b", filebuf[c2list_va_offset + 5 : c2list_va_offset + 6])[0]
            if tb == 0x48:
                delta += 1
        elif first_match(yara_matches, "$snippetB"):
            delta = 9
            refc2list = first_match(yara_matches, "$snippetB")
        elif first_match(yara_matches, "$snippetC"):
            delta = 8
            refc2list = first_match(yara_matches, "$snippetC")
        elif first_match(yara_matches, "$comboA1"):
            refc2list = first_match(yara_matches, "$comboA1")
        elif first_match(yara_matches, "$comboA2"):
            delta = 6
            refc2list = first_match(yara_matches, "$comboA2")

        if refc2list:
            c2list_va_offset = refc2list
            c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
            c2_list_rva = c2_list_va & 0xFFFF if c2_list_va - image_base > 0x40000 else c2_list_va - image_base
            try:
                c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
            except pefile.PEFormatError as err:
                log.error(err)
                return
            while True:
                preip = filebuf[c2_list_offset : c2_list_offset + 4]
                if not preip:
                    return
                try:
                    ip = struct.unpack("<I", preip)[0]
                except Exception as e:
                    log.error(e)
                    break
                if ip == 0:
                    break
                c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
                if not c2_address or not port:
                    break
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
                c2_list_offset += 8
    elif first_match(yara_matches, "$snippet6"):
        c2list_va_offset = first_match(yara_matches, "$snippet6")
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 15 : c2list_va_offset + 19])[0]
        c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError:
            pass
        while True:
            preip = filebuf[c2_list_offset : c2_list_offset + 4]
            if not preip:
                break
            try:
                ip = struct.unpack("<I", preip)[0]
            except Exception as e:
                log.error(e)
                break
            if ip == 0:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if not c2_address or not port:
                break
            conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2found = True
            c2_list_offset += 8
    elif first_match(yara_matches, "$snippet7"):
        c2list_va_offset = first_match(yara_matches, "$snippet7")
        delta = 26
        hb = struct.unpack("b", filebuf[c2list_va_offset + 29 : c2list_va_offset + 30])[0]
        if hb:
            delta += 1
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
        c2_list_rva = c2_list_va & 0xFFFF if c2_list_va - image_base > 0x20000 else c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError:
            pass
        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except Exception:
                break
            if ip == 0:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if not c2_address or not port:
                break
            conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2found = True
            c2_list_offset += 8
    elif first_match(yara_matches, "$snippetA"):
        c2list_va_offset = first_match(yara_matches, "$snippetA")
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 24 : c2list_va_offset + 28])[0]
        c2_list_rva = c2_list_va & 0xFFFF if c2_list_va - image_base > 0x20000 else c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError:
            pass
        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except Exception:
                break
            if ip == 0:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if not c2_address or not port:
                break
            conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2found = True
            c2_list_offset += 8
    elif first_match(yara_matches, "$snippetD"):
        delta = 6
        c2list_va_offset = first_match(yara_matches, "$snippetD")
    elif first_match(yara_matches, "$snippetE"):
        delta = 13
        c2list_va_offset = first_match(yara_matches, "$snippetE")
    elif first_match(yara_matches, "$snippetF"):
        delta = 9
        c2list_va_offset = first_match(yara_matches, "$snippetF")
    elif first_match(yara_matches, "$snippetG"):
        delta = -4
        c2list_va_offset = first_match(yara_matches, "$snippetG")
    elif first_match(yara_matches, "$snippetH"):
        delta = 12
        c2list_va_offset = first_match(yara_matches, "$snippetH")
    elif first_match(yara_matches, "$snippetI"):
        delta = -4
        c2list_va_offset = first_match(yara_matches, "$snippetI")
    elif first_match(yara_matches, "$snippetJ"):
        delta = 14
        c2list_va_offset = first_match(yara_matches, "$snippetJ")
    elif first_match(yara_matches, "$snippetK"):
        delta = -5
        c2list_va_offset = first_match(yara_matches, "$snippetK")
    elif first_match(yara_matches, "$snippetL"):
        delta = -4
        c2list_va_offset = first_match(yara_matches, "$snippetL")
    elif first_match(yara_matches, "$snippetM"):
        delta = 12
        c2list_va_offset = first_match(yara_matches, "$snippetM")
    elif first_match(yara_matches, "$snippetN"):
        delta = 9
        c2list_va_offset = first_match(yara_matches, "$snippetN")
    elif first_match(yara_matches, "$snippetO"):
        delta = 5
        c2list_va_offset = first_match(yara_matches, "$snippetO")
    elif first_match(yara_matches, "$snippetP"):
        delta = 17
        c2list_va_offset = first_match(yara_matches, "$snippetP")
    elif first_match(yara_matches, "$snippetQ"):
        delta = 5
        c2list_va_offset = first_match(yara_matches, "$snippetQ")
    elif first_match(yara_matches, "$snippetR"):
        delta = 18
        c2list_va_offset = first_match(yara_matches, "$snippetR")
    elif first_match(yara_matches, "$snippetS"):
        delta = -4
        c2list_va_offset = first_match(yara_matches, "$snippetS")
    elif first_match(yara_matches, "$snippetT"):
        delta = 13
        c2list_va_offset = first_match(yara_matches, "$snippetT")
    elif first_match(yara_matches, "$snippetU"):
        delta = 13
        c2list_va_offset = first_match(yara_matches, "$snippetU")
    elif first_match(yara_matches, "$snippetV"):
        delta = 14
        c2list_va_offset = first_match(yara_matches, "$snippetV")
    elif first_match(yara_matches, "$snippetW"):
        delta = 10
        c2_delta_offset = first_match(yara_matches, "$snippetW")
    elif first_match(yara_matches, "$snippetX"):
        delta = 3
        c2_delta_offset = first_match(yara_matches, "$snippetX")
    elif first_match(yara_matches, "$snippetY"):
        c2_funcs = c2_funcs_from_match(yara_matches, "$snippetY", filebuf)
    elif first_match(yara_matches, "$snippetZ"):
        c2_funcs = c2_funcs_from_match(yara_matches, "$snippetZ", filebuf)
    if delta:
        if c2list_va_offset:
            c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
            c2_list_rva = c2_list_va - image_base
            try:
                c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
            except pefile.PEFormatError as err:
                log.error(err)
                return
        elif c2_delta_offset:
            c2_delta = struct.unpack("i", filebuf[c2_delta_offset + delta : c2_delta_offset + delta + 4])[0]
            c2_list_rva = pe.get_rva_from_offset(c2_delta_offset) + c2_delta + delta + 4
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        key = filebuf[c2_list_offset : c2_list_offset + 4]
        presize = filebuf[c2_list_offset + 4 : c2_list_offset + 8]
        if not presize:
            return
        size = struct.unpack("I", presize)[0] ^ struct.unpack("I", key)[0]
        if size > 1000:
            log.debug("Anomalous C2 list size 0x%x", size)
            return
        c2_list_offset += 8
        c2_list = xor_data(filebuf[c2_list_offset:], key)
        offset = 0
        while offset < size:
            try:
                ip = struct.unpack(">I", c2_list[offset : offset + 4])[0]
            except Exception:
                break
            if ip == struct.unpack(">I", key)[0]:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack(">H", c2_list[offset + 4 : offset + 6])[0])
            if not c2_address or not port:
                break
            conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2found = True
            offset += 8
    elif c2_funcs:
        for address in c2_funcs:
            uc = emulate(code, address - pe.sections[0].PointerToRawData)
            c2_address = socket.inet_ntoa(struct.pack("!L", int.from_bytes(uc.mem_read(stack + 0x104, 4), byteorder="big")))
            flag = str(int.from_bytes(uc.mem_read(stack + 0x108, 2), byteorder="little"))
            port = str(int.from_bytes(uc.mem_read(stack + 0x10A, 2), byteorder="little"))
            if flag == "1" and port != "0":
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
            c2found = True

    if not c2found:
        return
    pem_key = False
    with suppress(ValueError):
        pem_key = extract_emotet_rsakey(pe)
    if pem_key:
        conf_dict.setdefault("RSA public key", pem_key.exportKey().decode())
    else:
        if first_match(yara_matches, "$ref_rsa"):
            ref_rsa_offset = first_match(yara_matches, "$ref_rsa")
            ref_rsa_va = 0
            zb = struct.unpack("b", filebuf[ref_rsa_offset + 31 : ref_rsa_offset + 32])[0]
            if not zb:
                ref_rsa_va = struct.unpack("I", filebuf[ref_rsa_offset + 28 : ref_rsa_offset + 32])[0]
            else:
                zb = struct.unpack("b", filebuf[ref_rsa_offset + 29 : ref_rsa_offset + 30])[0]
                if not zb:
                    ref_rsa_va = struct.unpack("I", filebuf[ref_rsa_offset + 26 : ref_rsa_offset + 30])[0]
                else:
                    zb = struct.unpack("b", filebuf[ref_rsa_offset + 28 : ref_rsa_offset + 29])[0]
                    if not zb:
                        ref_rsa_va = struct.unpack("I", filebuf[ref_rsa_offset + 25 : ref_rsa_offset + 29])[0]
                    else:
                        zb = struct.unpack("b", filebuf[ref_rsa_offset + 38 : ref_rsa_offset + 39])[0]
                        if not zb:
                            ref_rsa_va = struct.unpack("I", filebuf[ref_rsa_offset + 35 : ref_rsa_offset + 39])[0]
            if not ref_rsa_va:
                return
            ref_rsa_rva = ref_rsa_va - image_base
            try:
                ref_rsa_offset = pe.get_offset_from_rva(ref_rsa_rva)
            except Exception:
                return
            key = struct.unpack("<I", filebuf[ref_rsa_offset : ref_rsa_offset + 4])[0]
            xorsize = key ^ struct.unpack("<I", filebuf[ref_rsa_offset + 4 : ref_rsa_offset + 8])[0]
            rsa_key = xor_data(filebuf[ref_rsa_offset + 8 : ref_rsa_offset + 8 + xorsize], struct.pack("<I", key))
            seq = asn1.DerSequence()
            seq.decode(rsa_key)
            conf_dict.setdefault("RSA public key", RSA.construct((seq[0], seq[1])).exportKey())
        else:
            ref_ecc_offset = 0
            delta1 = 0
            delta2 = 0
            if first_match(yara_matches, "$ref_ecc1"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc1")
                delta1 = 9
                delta2 = 62
            elif first_match(yara_matches, "$ref_ecc2"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc2")
                delta1 = 22
                delta2 = 71
            elif first_match(yara_matches, "$ref_ecc3"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc3")
                delta1 = 8
                delta2 = 47
            elif first_match(yara_matches, "$ref_ecc4"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc4")
                delta1 = -4
                delta2 = 49
            elif first_match(yara_matches, "$ref_ecc5"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc5")
                delta1 = 15
                delta2 = 65
            elif first_match(yara_matches, "$ref_ecc6"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc6")
                delta1 = -4
                delta2 = 48
            elif first_match(yara_matches, "$ref_ecc7"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc7")
                delta1 = 23
                delta2 = 47
            elif first_match(yara_matches, "$ref_ecc8"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc8")
                delta1 = -5
                delta2 = 44
            elif first_match(yara_matches, "$ref_ecc9"):
                ref_ecc_offset = first_match(yara_matches, "$ref_ecc9")
                delta1 = -4
                delta2 = 24
            elif first_match(yara_matches, "$ref_eccA"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccA")
                delta1 = 12
                delta2 = 55
            elif first_match(yara_matches, "$ref_eccB"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccB")
                delta1 = 15
                delta2 = 58
            elif first_match(yara_matches, "$ref_eccC"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccC")
                delta1 = 8
                delta2 = 37
            elif first_match(yara_matches, "$ref_eccD"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccD")
                delta1 = 26
                delta2 = 72
            elif first_match(yara_matches, "$ref_eccE"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccE")
                delta1 = 8
                delta2 = 36
            elif first_match(yara_matches, "$ref_eccF"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccF")
                delta1 = -4
                delta2 = 48
            elif first_match(yara_matches, "$ref_eccG"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccG")
                delta1 = 30
                delta2 = 76
            if first_match(yara_matches, "$ref_eccH"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccH")
                delta1 = 9
                delta2 = 59
            if first_match(yara_matches, "$ref_eccI"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccI")
                delta1 = 22
                delta2 = 58
            if first_match(yara_matches, "$ref_eccJ"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccJ")
                delta1 = 10
                delta2 = 245
            if first_match(yara_matches, "$ref_eccK"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccK")
                delta1 = 14
                delta2 = 166
            if first_match(yara_matches, "$ref_eccK"):
                ref_ecc_offset = first_match(yara_matches, "$ref_eccK")
                delta1 = 14
                delta2 = 166
            if first_match(yara_matches, "$ref_eccL"):
                ecc_delta_offset = first_match(yara_matches, "$ref_eccL")
                delta1 = 8
                delta2 = 97
            if first_match(yara_matches, "$ref_eccM"):
                ecc_delta_offset = first_match(yara_matches, "$ref_eccM")
                delta1 = 3
                delta2 = 234
            if first_match(yara_matches, "$ref_eccN"):
                ecc_delta_offset = first_match(yara_matches, "$ref_eccN")
                delta1 = 3
                delta2 = 107
            if first_match(yara_matches, "$ref_eccO"):
                ecc_delta_offset = first_match(yara_matches, "$ref_eccO")
                delta1 = 3
                delta2 = 206
            if first_match(yara_matches, "$ref_eccP"):
                ecc_funcs = addresses_from_matches(yara_matches, "$ref_eccP")
            if delta1 or delta2:
                if ref_ecc_offset:
                    ref_eck_rva = struct.unpack("I", filebuf[ref_ecc_offset + delta1 : ref_ecc_offset + delta1 + 4])[0] - image_base
                    ref_ecs_rva = struct.unpack("I", filebuf[ref_ecc_offset + delta2 : ref_ecc_offset + delta2 + 4])[0] - image_base
                    try:
                        eck_offset = pe.get_offset_from_rva(ref_eck_rva)
                        ecs_offset = pe.get_offset_from_rva(ref_ecs_rva)
                    except Exception as e:
                        log.error(e)
                        return
                elif ecc_delta_offset:
                    eck_delta = struct.unpack("i", filebuf[ecc_delta_offset + delta1 : ecc_delta_offset + delta1 + 4])[0]
                    ecs_delta = struct.unpack("i", filebuf[ecc_delta_offset + delta2 : ecc_delta_offset + delta2 + 4])[0]
                    ref_eck_rva = pe.get_rva_from_offset(ecc_delta_offset) + eck_delta + delta1 + 4
                    ref_ecs_rva = pe.get_rva_from_offset(ecc_delta_offset) + ecs_delta + delta2 + 4
                    eck_offset = pe.get_offset_from_rva(ref_eck_rva)
                    ecs_offset = pe.get_offset_from_rva(ref_ecs_rva)
                key = filebuf[eck_offset : eck_offset + 4]
                size = struct.unpack("I", filebuf[eck_offset + 4 : eck_offset + 8])[0] ^ struct.unpack("I", key)[0]
                eck_offset += 8
                eck_key = xor_data(filebuf[eck_offset : eck_offset + size], key)
                key_len = struct.unpack("<I", eck_key[4:8])[0]
                conf_dict.setdefault(
                    "ECC ECK1",
                    ECC.construct(
                        curve="p256",
                        point_x=int.from_bytes(eck_key[8 : 8 + key_len], "big"),
                        point_y=int.from_bytes(eck_key[8 + key_len :], "big"),
                    ).export_key(format="PEM"),
                )
                key = filebuf[ecs_offset : ecs_offset + 4]
                size = struct.unpack("I", filebuf[ecs_offset + 4 : ecs_offset + 8])[0] ^ struct.unpack("I", key)[0]
                ecs_offset += 8
                ecs_key = xor_data(filebuf[ecs_offset : ecs_offset + size], key)
                key_len = struct.unpack("<I", ecs_key[4:8])[0]
                conf_dict.setdefault(
                    "ECC ECS1",
                    ECC.construct(
                        curve="p256",
                        point_x=int.from_bytes(ecs_key[8 : 8 + key_len], "big"),
                        point_y=int.from_bytes(ecs_key[8 + key_len :], "big"),
                    ).export_key(format="PEM"),
                )
            elif ecc_funcs:
                for func in ecc_funcs:
                    uc = emulate(code, func - pe.sections[0].PointerToRawData)
                    header = uc.mem_read(stack + 0x400, 8)
                    key_len = int.from_bytes(header[4:8], "little")
                    key = uc.mem_read(stack + 0x400, 2 * key_len + 8)
                    label = "ECC " + key[0:4].decode()
                    if label.startswith("EC"):
                        conf_dict.setdefault(
                            label,
                            ECC.construct(
                                curve="p256",
                                point_x=int.from_bytes(key[8 : 8 + key_len], "big"),
                                point_y=int.from_bytes(key[8 + key_len :], "big"),
                            ).export_key(format="PEM"),
                        )

    if "ECC ECK1" in conf_dict and "EFs0TIIEJgLTuqzx+58sdg==" in conf_dict["ECC ECK1"]:
        conf_dict.setdefault("Epoch", "4")
    if "ECC ECK1" in conf_dict and "OL7a+wCWnIQszh42gCRQlg==" in conf_dict["ECC ECK1"]:
        conf_dict.setdefault("Epoch", "5")

    return conf_dict


def test_them_all(path):
    import os

    if not os.path.exists(path):
        log.error("Path: %s doesn't exist", path)
        return

    for folder in os.listdir(path):
        snipped = os.path.join(path, folder)
        if not os.path.isdir(snipped):
            continue
        for sha256 in os.listdir(snipped):
            try:
                file = os.path.join(snipped, sha256)
                file_data = Path(file).read_bytes()
                result = extract_config(file_data)
                if result:
                    log.info("[+] %s", file)
                else:
                    log.info("[-] %s", file)
            except Exception as e:
                log.exception("%s - %s", file, e)


if __name__ == "__main__":
    import sys

    logging.basicConfig()
    log.setLevel(logging.DEBUG)
    if sys.argv[1] == "test":
        test_them_all(sys.argv[2])
    else:
        data = Path(sys.argv[1]).read_bytes()
        print(extract_config(data))
