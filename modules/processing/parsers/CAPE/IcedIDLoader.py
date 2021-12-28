# Copyright (C) 2021 kevoreilly, enzo
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

import os
import struct

import pefile
import yara

from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "IcedIDLoader.yar")
yara_rule = open(yara_path, "r").read()


def yara_scan(raw_data):
    try:
        addresses = {}
        yara_rules = yara.compile(source=yara_rule)
        matches = yara_rules.match(data=raw_data)
        return matches
    except Exception as e:
        print(e)


def iced_decode(data):
    n = 0
    new = []
    for x in data:
        k = data[n] ^ data[n + 64]
        new.append(k)
        if n > 32:
            break
        n += 1
    gads, d = struct.unpack("I30s", bytes(new))
    hostname = d.split(b"\00", 1)[0]
    return hostname


def config(filebuf):
    cfg = {}
    yara_hit = yara_scan(filebuf)
    for hit in yara_hit:
        if hit.rule == "IcedIDLoader":
            pe = pefile.PE(data=filebuf, fast_load=False)
            for section in pe.sections:
                if section.Name == b".d\x00\x00\x00\x00\x00\x00":
                    config_section = bytearray(section.get_data())
                    decoded = iced_decode(config_section).decode()
                    cfg["address"] = decoded
                    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    print(config(data))
