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
    temp = re.findall(rb"\x68...\x00.{1,10}\x68...\x00\x68...\x00\x68...\x00\x03\xc1", img)
    if temp != []:
        (addr,) = struct.unpack_from("<I", temp[0][1:])
        addr -= 0x400000
        iv = t[addr: addr + 8]
    return iv


def try_find_iv(pe):
    dlen = 8 * 4
    t = pe.get_memory_mapped_image() if isinstance(pe, pefile.PE) else pe
    off = t.find(b"\x6a\x08\x59\xbe")
    if off == -1:
        return -1
    (addr,) = struct.unpack_from("<I", t[off + 4:])
    # print(hex(addr))
    addr -= 0x400000

    # Go until past next blob to \x00\x00\x00\x00
    off = t[addr + dlen + 4:].find(b"\x00\x00\x00\x00")
    off += addr + dlen + 4 + 4
    iv = t[off: off + 8]

    # This doesn't work for all samples... still interesting that the data is in close proximity sometimes
    nul, key3, nul, key2, nul, key1 = struct.unpack_from("<I8sI8sI8s", t[off + 8:])

    # key = f"\x08\x02\x00\x00\x03\x66\x00\x00\x18\x00\x00\x00{key1}{key2}{key3}"

    return iv


def find_conf(pe):
    dlen = 8 * 4
    t = pe.get_memory_mapped_image() if isinstance(pe, pefile.PE) else pe
    off = t.find(b"\x6a\x08\x59\xbe")
    (addr,) = struct.unpack_from("<I", t[off + 4:])
    # print(hex(addr))
    addr -= 0x400000
    ret = [t[addr: addr + dlen]]
    dlen = 10 * 4
    off = t.find(b"\x6a\x0a\x59\xbe")
    (addr,) = struct.unpack_from("<I", t[off + 4:])
    # print(hex(addr))
    addr -= 0x400000
    ret.append(t[addr: addr + dlen])

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
                ret += t[addr: addr + 8]
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
    if x_sect is not None:
        x = img[x_sect.VirtualAddress: x_sect.VirtualAddress + x_sect.SizeOfRawData]
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
    if iv not in [b"", -1] and confs != []:
        for conf in confs:
            dec = DES3.new(key, DES3.MODE_CBC, iv)
            temp = dec.decrypt(conf)
            temp = unpad(temp, 8)
            urls.append(b"http://" + temp)
    return urls


def extract_config(filebuf):
    urls = decoder(filebuf)
    if urls:
        return {
            "family": "LokiBot",
            "http": [{'uri': url.decode(), 'usage': 'other'} for url in urls]
        }


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        data = f.read()

    print(extract_config(data))
