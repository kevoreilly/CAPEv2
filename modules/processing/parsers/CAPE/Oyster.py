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
import os
import re
import struct
from contextlib import suppress

import pefile
import yara

from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "Oyster.yar")
if not os.path.exists(yara_path):
    yara_path = os.path.join(CUCKOO_ROOT, "custom", "yara", "CAPE", "Oyster.yar")

with open(yara_path, "r") as yara_rule:
    yara_rules = yara.compile(source=yara_rule.read())

log = logging.getLogger(__name__)

DESCRIPTION = "Oyster configuration parser."
AUTHOR = "enzok"


def transform(src, lookup_table):
    length = len(src)
    i = 0
    num = length // 2
    if num > 0:
        pVal = length - 1
        while i < num:
            k = src[pVal]
            n = src[i]
            src[i] = lookup_table[k]
            i += 1
            result = lookup_table[n]
            src[pVal] = result
            pVal -= 1
    return src


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)


def extract_config(filebuf):
    yara_hit = yara_scan(filebuf)
    cfg = {}

    for hit in yara_hit:
        if hit.rule == "Oyster":
            start_offset = ""
            lookup_va = ""
            for item in hit.strings:
                if "$start_exit" == item.identifier:
                    start_offset = item.instances[0].offset
                if "$decode" == item.identifier:
                    decode_offset = item.instances[0].offset
                    lookup_va = filebuf[decode_offset + 12 : decode_offset + 16]
            if not (start_offset and lookup_va):
                return
            try:
                pe = pefile.PE(data=filebuf, fast_load=True)
                lookup_offset = pe.get_offset_from_rva(struct.unpack("I", lookup_va)[0] - pe.OPTIONAL_HEADER.ImageBase)
                lookup_table = filebuf[lookup_offset : lookup_offset + 256]
                data = filebuf[start_offset + 4 : start_offset + 8092]
                hex_strings = re.split(rb"\x00+", data)
                hex_strings = [s for s in hex_strings if s]
                str_vals = []
                c2 = []
                dll_version = ""

                for item in hex_strings:
                    with suppress(Exception):
                        decoded = transform(bytearray(item), bytearray(lookup_table)).decode("utf-8")
                    if not decoded:
                        continue
                    if "http" in decoded:
                        if "\r\n" in decoded:
                            c2.extend(list(filter(None, decoded.split("\r\n"))))
                        else:
                            c2.append(decoded)
                    elif "dll_version" in decoded:
                        dll_version = decoded.split('":"')[-1]
                    elif "api" in decoded or "Content-Type" in decoded:
                        str_vals.append(decoded)
                cfg = {
                    "C2": c2,
                    "Dll Version": dll_version,
                    "Strings": str_vals,
                }
            except Exception as e:
                log.error("Error: %s", e)
    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
