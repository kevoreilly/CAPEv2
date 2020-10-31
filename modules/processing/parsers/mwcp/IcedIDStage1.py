# Copyright (C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
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
#
# Updates to handle stage 1 Based on initial work referenced here and modified to work with python3
# https://sysopfb.github.io/malware,/icedid/2020/04/28/IcedIDs-updated-photoloader.html
# https://gist.github.com/sysopfb/93eb0090ef47c08e4e516cb045b48b96
#https://www.group-ib.com/blog/icedid

import os
import struct
import pefile
import yara
from Crypto.Cipher import ARC4
from mwcp.parser import Parser
from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "IcedIDStage1.yar")
yara_rule = open(yara_path, "r").read()

def yara_scan(raw_data):
    try:
        addresses = {}
        yara_rules = yara.compile(source=yara_rule)
        matches = yara_rules.match(data=raw_data)
        return matches
    except Exception as e:
        print(e)

def decode_stage1_config(data):
    out = ""
    for i in range(len(data)//2):
        t1 = data[i*2]
        t2 = data[(i*2)+1]
        t1 &= 0xf0
        t2 = t2 >> 4
        t1 |= t2
        t1 ^= (i & 0xff)
        out += chr(t1&0xff)

    return out

def parse_stage_1_domains(data):
    fakes = []
    real = []
    t = data[4:]
    print(type(t))

    (next, f) = struct.unpack_from('<BB', bytearray(t.encode()))

    while next != 0 and next < 100:
        if f == 0:
            real.append(t[2:].split('\x00')[0])
        else:
            fakes.append(t[2:].split('\00')[0])
        t = t[next:]
        (next, f) = struct.unpack_from(b'<BB', bytearray(t.encode()))

    return(fakes,real)

def rol(a, i):
    a &= 0xFFFFFFFF
    i &= 0x1F
    x = (((a << i) & 0xFFFFFFFF) | (a >> (32 - i))) & 0xFFFFFFFF
    return x


def ror(a, i):
    i &= 0x1F
    a &= 0xFFFFFFFF
    return (((a >> i) & 0xFFFFFFFF) | (a << ((32 - i)))) & 0xFFFFFFFF


def key_shift(key):
    key = ror(key, 1)
    key = ~key
    key = ror(key, 1)
    key -= 0x120
    key = rol(key, 1)
    key = ~key
    key -= 0x9101
    return key


def iced_decode(data, key, l):
    output = ""
    for i in range(l):
        key = key_shift(key)
        output += chr(struct.unpack("B", data[i : i + 1])[0] ^ (key & 0xFF))
    return output


class IcedIDStage1(Parser):

    DESCRIPTION = "IcedID configuration parser."
    AUTHOR = "kevoreilly,threathive,sysopfb"

    def run(self):
        filebuf = self.file_object.file_data
        yara_hit = yara_scan(filebuf)

        for hit in yara_hit:
            if hit.rule == "IcedIDStage1":
                pe = pefile.PE(data=filebuf, fast_load=False)
                for section in pe.sections:
                    if section.Name == b'.rdata\x00\x00':
                        config_section = bytearray(section.get_data())
                        cfg = decode_stage1_config(config_section[256:])
                        (f,r) = parse_stage_1_domains(cfg)
                        self.reporter.add_metadata("other", {"Version": "Stage 1/Photo Loader" })

                        if r:
                            for cnc in r:
                                self.reporter.add_metadata("other", {"CNC": cnc })
                        if f:
                            for decoy in f:
                                self.reporter.add_metadata("other", {"Decoy": decoy })
