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
from contextlib import suppress

import pefile
import yara

from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "Latrodectus.yar")
with open(yara_path, "r") as yara_rule:
    yara_rules = yara.compile(source=yara_rule.read())

log = logging.getLogger(__name__)

DESCRIPTION = "Latrodectus configuration parser."
AUTHOR = "enzok"


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)


def prng_seed(seed):
    sub_expr = (seed + 11865) << 31 | (seed + 11865) >> 1
    expr1 = (sub_expr << 31 | sub_expr >> 1) << 30 & (2**64 - 1)
    sub_expr = (expr1 & 0xFFFFFFFF) | (expr1 >> 32)
    expr2 = ((sub_expr ^ 0x151D) >> 30) | (4 * (sub_expr ^ 0x151D)) & (2**32 - 1)

    return ((expr2 >> 31) | (2 * expr2)) & 0xFFFFFFFF


def decrypt_string(data):
    seed = int.from_bytes(data[:4], "little") & 0xFFFFFFFF
    length = (int.from_bytes(data[4:6], "little")) ^ (int.from_bytes(data[:2], "little")) & 0xFFFF
    src = data[6:]
    result = bytearray()

    for i in range(length):
        byteval = src[i]
        seed = prng_seed(seed)
        result.append((seed ^ byteval) & 0xFF)
    return result


def fnv_hash(data):
    decode = 0x811C9DC5
    for key in data:
        decode = 0x1000193 * (decode ^ key) & 0xFFFFFFFF
    return decode


def extract_config(filebuf):
    yara_hit = yara_scan(filebuf)
    cfg = {}

    for hit in yara_hit:
        if hit.rule == "Latrodectus":
            try:
                pe = pefile.PE(data=filebuf, fast_load=True)
                data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
                if not data_sections:
                    return
                data = data_sections[0].get_data()
                if not data:
                    return
                hex_pattern = "".join([rf"{byte:02X}" for byte in data[:4]])
                regex = re.compile(hex_pattern.lower())
                matches = regex.finditer(data.hex())
                str_vals = []
                c2 = []
                for match in matches:
                    i = match.start() // 2
                    with suppress(Exception):
                        decoded = decrypt_string(data[i:])
                        if decoded:
                            str_val = decoded.decode("utf-8").replace("\00", "")
                            if "http" in str_val:
                                c2.append(str_val)
                            else:
                                str_vals.append(str_val)
                i = 0
                for val in str_vals:
                    if "/files/" in val:
                        break
                    else:
                        i += 1
                campaign = ""
                if ".exe" in str_vals[i + 2]:
                    campaign = str_vals[i + 1]
                cfg = {
                    "C2": c2,
                    "Group name": campaign,
                    "Campaign ID": fnv_hash(campaign.encode()),
                    "Strings": str_vals,
                }
            except Exception as e:
                log.error("Error: %s", e)
    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
