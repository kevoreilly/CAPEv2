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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


def initialize_key_schedule(key: bytes, iv: bytes) -> Cipher:
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    return cipher


def decrypt_with_ctr(cbc_cipher: Cipher, iv: bytes, data: bytes) -> bytes:
    key = cbc_cipher.algorithm.key
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext


def decrypt_string_aes(data: bytes, key: bytes) -> bytes:
    len_data = int.from_bytes(data[:2], "little")
    iv = data[2:18]
    data = data[18 : 18 + len_data]
    cbc_cipher = initialize_key_schedule(key, iv)
    decrypted_data = decrypt_with_ctr(cbc_cipher, iv, data)
    return decrypted_data


def prng_seed(seed):
    sub_expr = (seed + 11865) << 31 | (seed + 11865) >> 1
    expr1 = (sub_expr << 31 | sub_expr >> 1) << 30 & (2**64 - 1)
    sub_expr = (expr1 & 0xFFFFFFFF) | (expr1 >> 32)
    expr2 = ((sub_expr ^ 0x151D) >> 30) | (4 * (sub_expr ^ 0x151D)) & (2**32 - 1)
    return ((expr2 >> 31) | (2 * expr2)) & 0xFFFFFFFF


def decrypt_string(data, type):
    seed = int.from_bytes(data[:4], "little") & 0xFFFFFFFF
    length = (int.from_bytes(data[4:6], "little")) ^ (int.from_bytes(data[:2], "little")) & 0xFFFF
    src = data[6:]
    result = bytearray()

    for i in range(length):
        if type == 1:
            seed += 1
        elif type == 2:
            seed = prng_seed(seed)
        result.append((seed ^ src[i]) & 0xFF)
    return result


def get_aes_string(data, key):
    str_val = ""
    with suppress(Exception):
        str_val = decrypt_string_aes(data, key).decode("ascii").replace("\00", "")
    return str_val


def get_string(match, data):
    str_val = ""
    i = match.start() // 2
    with suppress(Exception):
        str_val = decrypt_string(data[i:], 1).decode("ascii").replace("\00", "")

    if not str_val:
        with suppress(Exception):
            str_val = decrypt_string(data[i:], 2).decode("ascii").replace("\00", "")

    return str_val


def fnv_hash(data):
    decode = 0x811C9DC5
    for key in data:
        decode = 0x1000193 * (decode ^ key) & 0xFFFFFFFF
    return decode


def extract_config(filebuf):
    yara_hit = yara_scan(filebuf)
    cfg = {}

    for hit in yara_hit:
        rule = hit.rule
        if "Latrodectus" in rule:
            version = ""
            is_aes = False
            key = ""
            if "AES" in rule:
                is_aes = True

            for item in hit.strings:
                for instance in item.instances:
                    if "$version" in item.identifier and not version:
                        data = instance.matched_data[::-1]
                        major = int.from_bytes(data[4:5], byteorder="big")
                        minor = int.from_bytes(data[12:13], byteorder="big")
                        version = f"{major}.{minor}"
                    if "$key" in item.identifier:
                        key = instance.matched_data[4::5]
            try:
                pe = pefile.PE(data=filebuf, fast_load=True)
                data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
                if not data_sections:
                    return
                data = data_sections[0].get_data()
                str_vals = []
                c2 = []
                campaign = ""
                rc4_key = ""

                if is_aes and key:
                    for i in range(len(data)):
                        str_val = get_aes_string(data[i : i + 256], key)
                        if str_val and len(str_val) > 2:
                            str_vals.append(str_val)
                else:
                    hex_pattern = "".join([rf"{byte:02X}" for byte in data[:4]])
                    regex = re.compile(hex_pattern.lower())
                    matches = regex.finditer(data.hex())

                    for match in matches:
                        str_val = get_string(match, data)
                        if str_val and len(str_val) > 2:
                            str_vals.append(str_val)

                for i in range(len(str_vals) - 1):
                    val = str_vals[i]
                    if "/files/" in val:
                        offset = 1
                        if is_aes:
                            offset += 1
                        campaign = str_vals[i + offset]
                    elif "ERROR" in val:
                        rc4_key = str_vals[i + 1]
                    elif "http" in val:
                        c2.append(val)

                for item in c2:
                    str_vals.remove(item)

                cfg = {
                    "C2": c2,
                    "Group name": campaign,
                    "Campaign ID": fnv_hash(campaign.encode()),
                    "Version": version,
                    "RC4 key": rc4_key,
                    "Strings": str_vals,
                }
            except Exception as e:
                log.error("Error: %s", e)
    return cfg


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
