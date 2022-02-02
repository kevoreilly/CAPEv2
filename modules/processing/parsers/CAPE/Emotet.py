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

import base64
import logging
import socket
import struct
from itertools import cycle

import pefile
import yara
from Crypto.PublicKey import RSA
from Crypto.Util import asn1

log = logging.getLogger()
log.setLevel(logging.INFO)

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
        $snippetD = {8D 44 [2] 50 68 [4] FF 74 [2] FF 74 [2] 8B 54 [2] 8B 4C [2] E8 [4] 8B 54 [2] 83 C4 10 89 44 [2] 8B F8 03 44 [2] B9 [4] 89 44 [2] E9 [2] FF FF}
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
    condition:
        uint16(0) == 0x5A4D and any of ($snippet*) or 2 of ($comboA*) or $ref_rsa or any of ($ref_ecc*)
}

"""

MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0


def yara_scan(raw_data):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Emotet":
            for item in match.strings:
                addresses[item[1]] = item[0]
    log.debug(addresses)
    return addresses


def xor_data(data, key):
    key = [q for q in key]
    data = [q for q in data]
    return bytes([c ^ k for c, k in zip(data, cycle(key))])


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
            pub_key = res_list[0][0:106]
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
            pub_key = res_list[0][0:106]
            seq = asn1.DerSequence()
            try:
                seq.decode(pub_key)
            except ValueError as e:
                log.error(e)
                return
            return RSA.construct((seq[0], seq[1]))


def config(filebuf):
    conf_dict = {}
    pe = pefile.PE(data=filebuf, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    c2found = False
    c2list_va_offset = 0
    delta = 0

    yara_matches = yara_scan(filebuf)
    if yara_matches.get("$snippet3"):
        c2list_va_offset = int(yara_matches["$snippet3"])
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 2 : c2list_va_offset + 6])[0]
        if c2_list_va - image_base > 0x20000:
            c2_list_va = c2_list_va & 0xFFFF
        else:
            c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
            pass

        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except:
                return
            if ip == 0:
                return
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if c2_address and port:
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
            else:
                return
            c2_list_offset += 8
    elif yara_matches.get("$snippet4"):
        c2list_va_offset = int(yara_matches["$snippet4"])
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 8 : c2list_va_offset + 12])[0]
        if c2_list_va - image_base > 0x20000:
            c2_list_rva = c2_list_va & 0xFFFF
        else:
            c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
            pass
        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except:
                return
            if ip == 0:
                return
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if c2_address and port:
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
            else:
                return
            c2_list_offset += 8
    elif any(
        [
            yara_matches.get(name, False)
            for name in ("$snippet5", "$snippet8", "$snippet9", "$snippetB", "$snippetC", "$comboA1", "$comboA2")
        ]
    ):
        delta = 5
        if yara_matches.get("$snippet5"):
            refc2list = yara_matches.get("$snippet5")
        elif yara_matches.get("$snippet8"):
            refc2list = yara_matches.get("$snippet8")
        elif yara_matches.get("$snippet9"):
            refc2list = yara_matches.get("$snippet8")
            c2list_va_offset = int(yara_matches["$snippet9"])
            tb = struct.unpack("b", filebuf[c2list_va_offset + 5 : c2list_va_offset + 6])[0]
            if tb == 0x48:
                delta += 1
        elif yara_matches.get("$snippetB"):
            delta = 9
            refc2list = yara_matches.get("$snippetB")
        elif yara_matches.get("$snippetC"):
            delta = 8
            refc2list = yara_matches.get("$snippetC")
        elif yara_matches.get("$comboA1"):
            refc2list = yara_matches.get("$comboA1")
        elif yara_matches.get("$comboA2"):
            delta = 6
            refc2list = yara_matches.get("$comboA2")

        if refc2list:
            c2list_va_offset = int(refc2list)
            c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
            if c2_list_va - image_base > 0x40000:
                c2_list_rva = c2_list_va & 0xFFFF
            else:
                c2_list_rva = c2_list_va - image_base
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
                if c2_address and port:
                    conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                    c2found = True
                else:
                    break
                c2_list_offset += 8
    elif yara_matches.get("$snippet6"):
        c2list_va_offset = int(yara_matches["$snippet6"])
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 15 : c2list_va_offset + 19])[0]
        c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
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
            if c2_address and port:
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
            else:
                break
            c2_list_offset += 8
    elif yara_matches.get("$snippet7"):
        c2list_va_offset = int(yara_matches["$snippet7"])
        delta = 26
        hb = struct.unpack("b", filebuf[c2list_va_offset + 29 : c2list_va_offset + 30])[0]
        if hb:
            delta += 1
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
        if c2_list_va - image_base > 0x20000:
            c2_list_rva = c2_list_va & 0xFFFF
        else:
            c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
            pass
        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except:
                break
            if ip == 0:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if c2_address and port:
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
            else:
                break
            c2_list_offset += 8
    elif yara_matches.get("$snippetA"):
        c2list_va_offset = int(yara_matches["$snippetA"])
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 24 : c2list_va_offset + 28])[0]
        if c2_list_va - image_base > 0x20000:
            c2_list_rva = c2_list_va & 0xFFFF
        else:
            c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
            pass
        while True:
            try:
                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
            except:
                break
            if ip == 0:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])
            if c2_address and port:
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
            else:
                break
            c2_list_offset += 8
    elif yara_matches.get("$snippetD"):
        delta = 6
        c2list_va_offset = int(yara_matches["$snippetD"])
    elif yara_matches.get("$snippetE"):
        delta = 13
        c2list_va_offset = int(yara_matches["$snippetE"])
    elif yara_matches.get("$snippetF"):
        delta = 9
        c2list_va_offset = int(yara_matches["$snippetF"])
    elif yara_matches.get("$snippetG"):
        delta = -4
        c2list_va_offset = int(yara_matches["$snippetG"])
    elif yara_matches.get("$snippetH"):
        delta = 12
        c2list_va_offset = int(yara_matches["$snippetH"])
    elif yara_matches.get("$snippetI"):
        delta = -4
        c2list_va_offset = int(yara_matches["$snippetI"])
    elif yara_matches.get("$snippetJ"):
        delta = 14
        c2list_va_offset = int(yara_matches["$snippetJ"])
    elif yara_matches.get("$snippetK"):
        delta = -5
        c2list_va_offset = int(yara_matches["$snippetK"])
    elif yara_matches.get("$snippetL"):
        delta = -4
        c2list_va_offset = int(yara_matches["$snippetL"])
    elif yara_matches.get("$snippetM"):
        delta = 12
        c2list_va_offset = int(yara_matches["$snippetM"])
    elif yara_matches.get("$snippetN"):
        delta = 9
        c2list_va_offset = int(yara_matches["$snippetN"])
    elif yara_matches.get("$snippetO"):
        delta = 5
        c2list_va_offset = int(yara_matches["$snippetO"])

    if c2list_va_offset and delta:
        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
        c2_list_rva = c2_list_va - image_base
        try:
            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
        except pefile.PEFormatError as err:
            log.error(err)
            return
        key = filebuf[c2_list_offset : c2_list_offset + 4]
        presize = filebuf[c2_list_offset + 4 : c2_list_offset + 8]
        if not presize:
            return
        size = struct.unpack("I", presize)[0] ^ struct.unpack("I", key)[0]
        if size > 500:
            log.info("Anomalous C2 list size 0x%x", size)
            return
        c2_list_offset += 8
        c2_list = xor_data(filebuf[c2_list_offset:], key)
        offset = 0
        while offset < size:
            try:
                ip = struct.unpack(">I", c2_list[offset : offset + 4])[0]
            except:
                break
            if ip == struct.unpack(">I", key)[0]:
                break
            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
            port = str(struct.unpack(">H", c2_list[offset + 4 : offset + 6])[0])
            if c2_address and port:
                conf_dict.setdefault("address", []).append(f"{c2_address}:{port}")
                c2found = True
            else:
                break
            offset += 8

    if not c2found:
        return
    pem_key = False
    try:
        pem_key = extract_emotet_rsakey(pe)
    except ValueError as e:
        log.error(e)
    if pem_key:
        # self.reporter.add_metadata("other", {"RSA public key": pem_key.exportKey().decode()})
        conf_dict.setdefault("RSA public key", pem_key.exportKey().decode())
    else:
        if yara_matches.get("$ref_rsa"):
            ref_rsa_offset = int(yara_matches["$ref_rsa"])
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
            except:
                return
            key = struct.unpack("<I", filebuf[ref_rsa_offset : ref_rsa_offset + 4])[0]
            xorsize = key ^ struct.unpack("<I", filebuf[ref_rsa_offset + 4 : ref_rsa_offset + 8])[0]
            rsa_key = xor_data(filebuf[ref_rsa_offset + 8 : ref_rsa_offset + 8 + xorsize], struct.pack("<I", key))
            seq = asn1.DerSequence()
            seq.decode(rsa_key)
            # self.reporter.add_metadata("other", {"RSA public key": RSA.construct((seq[0], seq[1])).exportKey()})
            conf_dict.setdefault("RSA public key", RSA.construct((seq[0], seq[1])).exportKey())
        else:
            ref_ecc_offset = 0
            if yara_matches.get("$ref_ecc1"):
                ref_ecc_offset = int(yara_matches["$ref_ecc1"])
                delta1 = 9
                delta2 = 62
            elif yara_matches.get("$ref_ecc2"):
                ref_ecc_offset = int(yara_matches["$ref_ecc2"])
                delta1 = 22
                delta2 = 71
            elif yara_matches.get("$ref_ecc3"):
                ref_ecc_offset = int(yara_matches["$ref_ecc3"])
                delta1 = 8
                delta2 = 47
            elif yara_matches.get("$ref_ecc4"):
                ref_ecc_offset = int(yara_matches["$ref_ecc4"])
                delta1 = -4
                delta2 = 49
            elif yara_matches.get("$ref_ecc5"):
                ref_ecc_offset = int(yara_matches["$ref_ecc5"])
                delta1 = 15
                delta2 = 65
            elif yara_matches.get("$ref_ecc6"):
                ref_ecc_offset = int(yara_matches["$ref_ecc6"])
                delta1 = -4
                delta2 = 48
            elif yara_matches.get("$ref_ecc7"):
                ref_ecc_offset = int(yara_matches["$ref_ecc7"])
                delta1 = 23
                delta2 = 47
            elif yara_matches.get("$ref_ecc8"):
                ref_ecc_offset = int(yara_matches["$ref_ecc8"])
                delta1 = -5
                delta2 = 44
            elif yara_matches.get("$ref_ecc9"):
                ref_ecc_offset = int(yara_matches["$ref_ecc9"])
                delta1 = -4
                delta2 = 24
            elif yara_matches.get("$ref_eccA"):
                ref_ecc_offset = int(yara_matches["$ref_eccA"])
                delta1 = 12
                delta2 = 55
            elif yara_matches.get("$ref_eccB"):
                ref_ecc_offset = int(yara_matches["$ref_eccB"])
                delta1 = 15
                delta2 = 58
            elif yara_matches.get("$ref_eccC"):
                ref_ecc_offset = int(yara_matches["$ref_eccC"])
                delta1 = 8
                delta2 = 37
            if ref_ecc_offset:
                ref_eck_rva = struct.unpack("I", filebuf[ref_ecc_offset + delta1 : ref_ecc_offset + delta1 + 4])[0] - image_base
                ref_ecs_rva = struct.unpack("I", filebuf[ref_ecc_offset + delta2 : ref_ecc_offset + delta2 + 4])[0] - image_base
                try:
                    eck_offset = pe.get_offset_from_rva(ref_eck_rva)
                    ecs_offset = pe.get_offset_from_rva(ref_ecs_rva)
                except Exception as e:
                    log.error(e)
                    return
                key = filebuf[eck_offset : eck_offset + 4]
                size = struct.unpack("I", filebuf[eck_offset + 4 : eck_offset + 8])[0] ^ struct.unpack("I", key)[0]
                eck_offset += 8
                eck_key = base64.b64encode(xor_data(filebuf[eck_offset : eck_offset + size], key))
                # self.reporter.add_metadata("other", {"ECC ECK1": eck_key})
                conf_dict.setdefault("ECC ECK1", eck_key.decode("latin-1"))
                key = filebuf[ecs_offset : ecs_offset + 4]
                size = struct.unpack("I", filebuf[ecs_offset + 4 : ecs_offset + 8])[0] ^ struct.unpack("I", key)[0]
                ecs_offset += 8
                ecs_key = base64.b64encode(xor_data(filebuf[ecs_offset : ecs_offset + size], key))
                # self.reporter.add_metadata("other", {"ECC ECS1": ecs_key})
                conf_dict.setdefault("ECC ECS1", ecs_key.decode("latin-1"))
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
                with open(file, "rb") as f:
                    file_data = f.read()

                result = config(file_data)
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
        file_data = open(sys.argv[1], "rb").read()
        print(config(file_data))
