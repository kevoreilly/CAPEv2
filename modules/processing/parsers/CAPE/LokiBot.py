# MIT License
#
# Copyright (c) Jason Reaves - @sysopfb
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import struct
import sys

import pefile
from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import unpad

DESCRIPTION = "LokiBot configuration parser."
AUTHOR = "sysopfb"


def find_iv(img):
    iv = b""
    temp = re.findall(rb"\x68...\x00.{1,10}\x68...\x00\x68...\x00\x68...\x00\x03\xc1", img)
    if temp != []:
        (addr,) = struct.unpack_from("<I", temp[0][1:])
        addr -= 0x400000
        iv = img[addr : addr + 8]
    return iv


def find_conf(img):
    ret = []

    num_addr_re1 = re.compile(
        rb"""
        \x6A(?P<num>.)      # 6A 08                push    8
        \x59                # 59                   pop     ecx
        \xBE(?P<addr>.{4})  # BE D0 88 41 00       mov     esi, offset encrypted_data1
        \x8D\xBD.{4}        # 8D BD 68 FE FF FF    lea     edi, [ebp+encrypted_data_list]
        \xF3\xA5            # F3 A5                rep movsd
        \x6A.               # 6A 43                push    43h ; 'C'
        \x5B                # 5B                   pop     ebx
        \x53                # 53                   push    ebx
        \x8D\x85.{4}        # 8D 85 89 FE FF FF    lea     eax, [ebp+var_177]
        \xA4                # A4                   movsb
        \x6A\x00            # 6A 00                push    0
        \x50                # 50                   push    eax
        \xE8.{4}            # E8 78 E9 FE FF       call    about_memset
        """,
        re.DOTALL | re.VERBOSE,
    )
    num_addr_re2 = re.compile(
        rb"""
        \x6A(?P<num>.)      # 6A 08                push    8
        \x59                # 59                   pop     ecx
        \xBE(?P<addr>.{4})  # BE F4 88 41 00       mov     esi, offset encrypted_data2
        \x8D.{2,5}          # 8D BD CC FE FF FF    lea     edi, [ebp+var_134]
        \xF3\xA5            # F3 A5                rep movsd
        \x53                # 53                   push    ebx
        \x8D.{2,5}          # 8D 85 ED FE FF FF    lea     eax, [ebp+var_113]
        \x6A\x00            # 6A 00                push    0
        \x50                # 50                   push    eax
        \xA4                # A4                   movsb
        \xE8.{4}            # E8 58 E9 FE FF       call    about_memset
        """,
        re.DOTALL | re.VERBOSE,
    )

    num_addr_list = re.findall(num_addr_re1, img)
    num_addr_list.extend(re.findall(num_addr_re2, img))

    for num, addr in num_addr_list:
        dlen = ord(num) * 4
        (addr,) = struct.unpack_from("<I", addr)
        # print(hex(addr))
        addr -= 0x400000
        data = img[addr : addr + dlen]
        ret.append(data)

    return ret


def find_key(img):
    ret = None
    temp = re.findall(rb"\x68...\x00\x68...\x00\x68...\x00\x03\xc1", img)
    if temp != []:
        ret = b""
        temp = temp[0][:-2].split(b"\x68")[::-1]
        for a in temp:
            if a != b"":
                (addr,) = struct.unpack_from("<I", a)
                # print(hex(addr))
                addr -= 0x400000
                ret += img[addr : addr + 8]
    return ret


def decoder(data):
    x_sect = None
    urls = []

    try:
        pe = pefile.PE(data=data)

        for sect in pe.sections:
            if sect.Name.strip(b"\x00") == b".x":
                x_sect = sect
        img = pe.get_memory_mapped_image()
    except Exception:
        img = data
    if x_sect:
        x = img[x_sect.VirtualAddress : x_sect.VirtualAddress + x_sect.SizeOfRawData]
        x = bytearray(x)
    else:
        x = bytearray(img)

    url_re = rb"https?:\/\/[a-zA-Z0-9\/\.:?\-_]+"
    urls = re.findall(url_re, x)
    if not urls:
        for i in range(len(x)):
            x[i] ^= 0xFF

        temp = re.findall(url_re, x)
        for url in temp:
            urls.append(url)

    # Try to decrypt onboard config
    key = find_key(img)
    iv = find_iv(img)
    confs = find_conf(img)
    if iv and iv not in (b"", -1) and confs != []:
        for conf in confs:
            try:
                dec = DES3.new(key, DES3.MODE_CBC, iv)
                temp = dec.decrypt(conf)
                temp = unpad(temp, 8)
                urls.append(b"http://" + temp)
            except ValueError:
                # wrong padding
                pass
    return urls


def extract_config(filebuf):

    urls = decoder(filebuf)
    return {"address": [url.decode() for url in urls]}


if __name__ == "__main__":
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
