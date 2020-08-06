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

from mwcp.parser import Parser
import pefile
import sys
import re
import struct
from Crypto.Cipher import DES3


def find_iv(pe):
    iv = -1
    if type(pe) == pefile.PE:
        t = pe.get_memory_mapped_image()
    else:
        t = pe
    temp = re.findall(br"""\x68...\x00.{1,10}\x68...\x00\x68...\x00\x68...\x00\x03\xc1""", t)
    if temp != []:
        (addr,) = struct.unpack_from("<I", temp[0][1:])
        addr -= 0x400000
        iv = t[addr : addr + 8]
    return iv


def try_find_iv(pe):
    ret = []

    dlen = 8 * 4
    if type(pe) == pefile.PE:
        t = pe.get_memory_mapped_image()
    else:
        t = pe
    off = t.find(b"\x6a\x08\x59\xbe")
    if off == -1:
        return -1
    (addr,) = struct.unpack_from("<I", t[off + 4 :])
    # print(hex(addr))
    addr -= 0x400000
    conf = t[addr : addr + dlen]

    # Go until past next blob to \x00\x00\x00\x00
    off = t[addr + dlen + 4 :].find(b"\x00\x00\x00\x00")
    off += addr + dlen + 4 + 4
    iv = t[off : off + 8]

    # This doesn't work for all samples... still interesting that the data is in close proximity sometimes
    (nul, key3, nul, key2, nul, key1) = struct.unpack_from("<I8sI8sI8s", t[off + 8 :])

    key = "\x08\x02\x00\x00\x03\x66\x00\x00\x18\x00\x00\x00" + key1 + key2 + key3

    return iv


def find_conf(pe):
    ret = []

    dlen = 8 * 4
    if type(pe) == pefile.PE:
        t = pe.get_memory_mapped_image()
    else:
        t = pe
    off = t.find(b"\x6a\x08\x59\xbe")
    (addr,) = struct.unpack_from("<I", t[off + 4 :])
    # print(hex(addr))
    addr -= 0x400000
    data = t[addr : addr + dlen]
    ret.append(data)

    dlen = 10 * 4
    off = t.find(b"\x6a\x0a\x59\xbe")
    (addr,) = struct.unpack_from("<I", t[off + 4 :])
    # print(hex(addr))
    addr -= 0x400000
    data = t[addr : addr + dlen]
    ret.append(data)

    return ret


def find_key(pe):
    ret = None
    if type(pe) == pefile.PE:
        t = pe.get_memory_mapped_image()
    else:
        t = pe
    temp = re.findall(br"""\x68...\x00\x68...\x00\x68...\x00\x03\xc1""", t)
    if temp != []:
        ret = "\x08\x02\x00\x00\x03\x66\x00\x00\x18\x00\x00\x00"
        temp = temp[0][:-2].split("\x68")[::-1]
        for a in temp:
            if a != "":
                (addr,) = struct.unpack_from("<I", a)
                # print(hex(addr))
                addr -= 0x400000
                ret += t[addr : addr + 8]
    return ret


def decoder(data):
    x_sect = None

    urls = re.findall(br"""https?:\/\/[a-zA-Z0-9\/\.:\-_]+""", data)

    pe = None
    try:
        pe = pefile.PE(sys.argv[1])

        for sect in pe.sections:
            if ".x" in sect.Name:
                x_sect = sect
        img = pe.get_memory_mapped_image()
    except:
        img = data
    if x_sect != None:
        x = img[x_sect.VirtualAddress : x_sect.VirtualAddress + x_sect.SizeOfRawData]
        x = bytearray(x)
    else:
        x = bytearray(img)

    for i in range(len(x)):
        x[i] ^= 0xFF

    temp = re.findall(br"""https?:\/\/[a-zA-Z0-9\/\.:\-_]+""", x)
    urls += temp

    urls = [x for x in urls if x != "http://www.ibsensoftware.com/" and x != ""]

    # Try to decrypt onboard config then
    if urls == []:
        temp = ""
        if pe == None:
            pe = data
        key = find_key(pe)
        # iv = try_find_iv(pe)
        iv = find_iv(pe)
        confs = find_conf(pe)
        if iv not in ["", -1] and confs != []:
            for conf in confs:
                dec = DES3.new(key[12:], DES3.MODE_CBC, iv)
                temp += dec.decrypt(conf)
            temp_urls = re.findall(br"""[a-zA-Z0-9\/\.:\-_]{6,}""", temp)
            urls += temp_urls

    return urls


class Loki(Parser):

    DESCRIPTION = "Loki configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        urls = decoder(self.file_object.file_data)
        for url in urls:
            self.reporter.add_metadata("address", url)
