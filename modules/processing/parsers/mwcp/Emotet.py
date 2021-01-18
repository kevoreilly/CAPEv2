# Copyright (C) 2017-2019 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
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
import socket
import pefile
import yara
import re
from Crypto.Util import asn1
from Crypto.PublicKey import RSA
from itertools import cycle

rule_source = """
rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"
    strings:
        $snippet1 = {FF 15 ?? ?? ?? ?? 83 C4 0C 68 40 00 00 F0 6A 18}
        $snippet2 = {6A 13 68 01 00 01 00 FF 15 ?? ?? ?? ?? 85 C0}
        $snippet3 = {83 3D ?? ?? ?? ?? 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 74 0A 51 E8 ?? ?? ?? ?? 83 C4 04 C3 33 C0 C3}
        $snippet4 = {33 C0 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? 00 75 F0 51 E8 ?? ?? ?? ?? 83 C4 04 C3}
        $snippet5 = {8B E5 5D C3 B8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 21 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 18 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? 00 75 F0 51 E8 ?? ?? ?? ?? 59 C3}
        $snippet6 = {33 C0 21 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 74 18 40 A3 ?? ?? ?? ?? 83 3C C5 ?? ?? ?? ?? 00 75 F0 51 E8 ?? ?? ?? ?? 59 C3}
        $snippet7 = {8B 48 ?? C7 [5-6] C7 40 ?? ?? ?? ?? ?? C7 ?? ?? 00 00 00 [0-1] 83 3C CD ?? ?? ?? ?? 00 74 0E 41 89 48 ?? 83 3C CD ?? ?? ?? ?? 00 75 F2}
        $snippet8 = {85 C0 74 3? B9 [2] 40 00 33 D2 89 ?8 [0-1] 89 [1-2] 8B [1-2] 89 [1-2] EB 0? 41 89 [1-2] 39 14 CD [2] 40 00 75 F? 8B CE E8 [4] 85 C0 74 05 33 C0 40 5E C3}
        $snippet9 = {85 C0 74 4? 8B ?8 [0-1] C7 40 [5] C7 [5-6] C7 40 ?? 00 00 00 00 83 3C CD [4] 00 74 0? 41 89 [2-3] 3C CD [4] 00 75 F? 8B CF E8 [4] 85 C0 74 07 B8 01 00 00 00 5F C3}
        $snippetA = {85 C0 74 5? 8B ?8 04 89 78 28 89 38 89 70 2C EB 04 41 89 48 04 39 34 CD [4] 75 F3 FF 75 DC FF 75 F0 8B 55 F8 FF 75 10 8B 4D EC E8 [4] 83 C4 0C 85 C0 74 05}
        $snippetB = {EB 04 4? 89 4? ?? 39 [6] 75 F3}
        $ref_rsa = {6A 00 6A 01 FF [4-9] C0 [5-11] E8 ?? ?? FF FF 8D 4? [1-2] B9 ?? ?? ?? 00 8D 5? [4-6] E8}
    condition:
        uint16(0) == 0x5A4D and (($snippet1) and ($snippet2)) or ($snippet3) or ($snippet4) or ($snippet5) or ($snippet6) or ($snippet7) or ($snippet8) or ($snippet9) or ($snippetA) or ($snippetB) or ($ref_rsa)
}

"""

MAX_IP_STRING_SIZE = 16  # aaa.bbb.ccc.ddd\0

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Emotet":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses

def xor_data(data, key):
    key = [q for q in key]
    data = [q for q in data]
    return bytes([c ^ k for c, k in zip(data, cycle(key))])

# This function is originally by Jason Reaves (@sysopfb),
# suggested as an addition by @pollo290987, updated by
# phate1. A big thank you to all.
def extract_emotet_rsakey(pe):
    for section in pe.sections:
        if section.Name.replace(b'\x00',b'') == b'.data':
            data_section = section.get_data()
    pub_matches = re.findall(b"""\x00{4,12}(?=([\x01-\xff][\x00-\xff]{120}))""", data_section)
    if pub_matches:
        res_list = []
        for match in pub_matches:
            xor_key = int.from_bytes(match[:4], byteorder='little')
            encoded_size = int.from_bytes(match[4:8], byteorder='little')
            decoded_size = ((xor_key ^ encoded_size)&0xfffffffc)+4
            if decoded_size == 0x6c:
                offset = 8
                res = b''
                for count in range(int(0x6c/4)):
                    off_from = offset+count*4
                    off_to = off_from+4
                    encoded_dw = int.from_bytes(match[off_from:off_to], byteorder='little')
                    decoded = xor_key ^ encoded_dw
                    res = res + decoded.to_bytes(4, byteorder='little')
                res_list.append(res)

        res_list = list(set(res_list))
        pub_key = res_list[0][0:106]
        seq = asn1.DerSequence()
        seq.decode(pub_key)
        return RSA.construct((seq[0], seq[1]))

class Emotet(Parser):
    # def __init__(self, reporter=None):
    #    Parser.__init__(self, description='Emotet configuration parser.', author='kevoreilly', reporter=reporter)

    DESCRIPTION = "Emotet configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        c2found = False

        c2list = yara_scan(filebuf, "$c2list")
        if c2list:
            ips_offset = int(c2list["$c2list"])

            ip = struct.unpack("I", filebuf[ips_offset : ips_offset + 4])[0]

            while ip:
                c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                port = str(struct.unpack("h", filebuf[ips_offset + 4 : ips_offset + 6])[0])

                if c2_address and port:
                    self.reporter.add_metadata("address", c2_address + ":" + port)
                    c2found = True

                ips_offset += 8
                ip = struct.unpack("I", filebuf[ips_offset : ips_offset + 4])[0]
        else:
            refc2list = yara_scan(filebuf, "$snippet3")
        if refc2list:
            c2list_va_offset = int(refc2list["$snippet3"])
            c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 2 : c2list_va_offset + 6])[0]
            if c2_list_va - image_base > 0x20000:
                c2_list_va = c2_list_va & 0xFFFF
            else:
                c2_list_rva = c2_list_va - image_base
            try:
                c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
            except pefile.PEFormatError as err:
                pass

            while 1:
                try:
                    ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
                except:
                    return
                if ip == 0:
                    return
                c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])

                if c2_address and port:
                    self.reporter.add_metadata("address", c2_address + ":" + port)
                    c2found = True
                else:
                    return
                c2_list_offset += 8
        else:
            refc2list = yara_scan(filebuf, "$snippet4")
            if refc2list:
                c2list_va_offset = int(refc2list["$snippet4"])
                c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 8 : c2list_va_offset + 12])[0]
                if c2_list_va - image_base > 0x20000:
                    c2_list_rva = c2_list_va & 0xFFFF
                else:
                    c2_list_rva = c2_list_va - image_base
                try:
                    c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
                except pefile.PEFormatError as err:
                    pass

                while 1:
                    try:
                        ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
                    except:
                        return
                    if ip == 0:
                        return
                    c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                    port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])

                    if c2_address and port:
                        self.reporter.add_metadata("address", c2_address + ":" + port)
                        c2found = True
                    else:
                        return
                    c2_list_offset += 8
            else:
                snippet = "$snippet5"
                delta = 5
                refc2list = yara_scan(filebuf, snippet)
                if not refc2list:
                    snippet = "$snippet8"
                    refc2list = yara_scan(filebuf, snippet)
                if not refc2list:
                    snippet = "$snippet9"
                    delta = 9
                    refc2list = yara_scan(filebuf, snippet)
                    if refc2list:
                        c2list_va_offset = int(refc2list[snippet])
                        tb = struct.unpack("b", filebuf[c2list_va_offset+5:c2list_va_offset+6])[0]
                        if tb == 0x48:
                            delta += 1
                if not refc2list:
                    snippet = "$snippetB"
                    delta = 9
                    refc2list = yara_scan(filebuf, snippet)
                if refc2list:
                    c2list_va_offset = int(refc2list[snippet])
                    c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + delta : c2list_va_offset + delta + 4])[0]
                    if c2_list_va - image_base > 0x20000:
                        c2_list_rva = c2_list_va & 0xFFFF
                    else:
                        c2_list_rva = c2_list_va - image_base
                    try:
                        c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
                    except pefile.PEFormatError as err:
                        return
                    while 1:
                        try:
                            ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
                        except:
                            break
                        if ip == 0:
                            break
                        c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                        port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])

                        if c2_address and port:
                            self.reporter.add_metadata("address", c2_address + ":" + port)
                            c2found = True
                        else:
                            break
                        c2_list_offset += 8
                else:
                    refc2list = yara_scan(filebuf, "$snippet6")
                    if refc2list:
                        c2list_va_offset = int(refc2list["$snippet6"])
                        c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 15 : c2list_va_offset + 19])[0]
                        if c2_list_va - image_base > 0x20000:
                            c2_list_rva = c2_list_va & 0xFFFF
                        else:
                            c2_list_rva = c2_list_va - image_base
                        try:
                            c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
                        except pefile.PEFormatError as err:
                            pass
                        while 1:
                            try:
                                ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
                            except:
                                break
                            if ip == 0:
                                break
                            c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                            port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])

                            if c2_address and port:
                                self.reporter.add_metadata("address", c2_address + ":" + port)
                                c2found = True
                            else:
                                break
                            c2_list_offset += 8
                    else:
                        refc2list = yara_scan(filebuf, "$snippet7")
                        if refc2list:
                            c2list_va_offset = int(refc2list["$snippet7"])
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
                            while 1:
                                try:
                                    ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
                                except:
                                    break
                                if ip == 0:
                                    break
                                c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                                port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])

                                if c2_address and port:
                                    self.reporter.add_metadata("address", c2_address + ":" + port)
                                    c2found = True
                                else:
                                    break
                                c2_list_offset += 8
                        else:
                            refc2list = yara_scan(filebuf, "$snippetA")
                            if refc2list:
                                c2list_va_offset = int(refc2list["$snippetA"])
                                c2_list_va = struct.unpack("I", filebuf[c2list_va_offset + 24 : c2list_va_offset + 28])[0]
                                if c2_list_va - image_base > 0x20000:
                                    c2_list_rva = c2_list_va & 0xFFFF
                                else:
                                    c2_list_rva = c2_list_va - image_base
                                try:
                                    c2_list_offset = pe.get_offset_from_rva(c2_list_rva)
                                except pefile.PEFormatError as err:
                                    pass

                                while 1:
                                    try:
                                        ip = struct.unpack("<I", filebuf[c2_list_offset : c2_list_offset + 4])[0]
                                    except:
                                        return
                                    if ip == 0:
                                        return
                                    c2_address = socket.inet_ntoa(struct.pack("!L", ip))
                                    port = str(struct.unpack("H", filebuf[c2_list_offset + 4 : c2_list_offset + 6])[0])

                                    if c2_address and port:
                                        self.reporter.add_metadata("address", c2_address + ":" + port)
                                        c2found = True
                                    else:
                                        return
                                    c2_list_offset += 8

        if not c2found:
            return
        pem_key = extract_emotet_rsakey(pe)
        if pem_key:
            self.reporter.add_metadata("other", {"RSA public key": pem_key.exportKey().decode('utf8')})
        else:
            ref_rsa = yara_scan(filebuf, "$ref_rsa")
            if ref_rsa:
                ref_rsa_offset = int(ref_rsa["$ref_rsa"])
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
                self.reporter.add_metadata("other", {"RSA public key": RSA.construct((seq[0], seq[1])).exportKey()})
