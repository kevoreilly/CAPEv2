import logging
import re
import struct
from contextlib import suppress

import pefile

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def initialize_sbox(key, keysize):
    sbox = bytearray(258)
    sbox[0] = 0
    sbox[1] = 0

    for i in range(256):
        sbox[i + 2] = i

    k = 0
    for j in range(256):
        k = (k + (key[j % keysize] + sbox[j + 2])) % 256
        sbox[j + 2], sbox[k + 2] = sbox[k + 2], sbox[j + 2]

    return sbox


def decrypt(sbox, data, size):
    decoded_string = bytearray(size)

    i = 0
    while i < size:
        sbox[0] = (sbox[0] + 1) % 256
        sbox[1] = (sbox[1] + sbox[(sbox[0] + 2) % len(sbox)]) % 256
        temp_index1 = sbox[0] % 256 + 2
        temp_index2 = sbox[1] % 256 + 2
        sbox[temp_index1], sbox[temp_index2] = sbox[temp_index2], sbox[temp_index1]
        final_index = (sbox[temp_index2] + sbox[temp_index1]) % 256 + 2
        decoded_string[i] = (sbox[final_index] ^ data[i])
        i += 1

    return decoded_string


def is_hex(hex_string):
    if len(hex_string) % 2 != 0:
        return False

    if not re.fullmatch(r'[0-9a-fA-F]+', hex_string):
        return False

    return True


def extract_config(filebuf):
    cfg = {}
    pe = pefile.PE(data=filebuf)

    data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]

    if not data_sections:
        return None

    data = data_sections[0].get_data()

    offset = 0
    entries = []
    while offset < len(data):
        if offset + 8 > len(data):
            break
        size, key = struct.unpack_from("I4s", data, offset)
        if b"\x00\x00\x00" in key or size > 256:
            offset += 4
            continue
        offset += 8
        data_format = f"{size}s"
        encrypted_string = struct.unpack_from(data_format, data, offset)[0]
        offset += size
        padding = (8 - (offset % 8)) % 8
        offset += padding

        with suppress(IndexError, UnicodeDecodeError, ValueError):
            sbox = bytearray(initialize_sbox(key, 4))
            decrypted_result = decrypt(sbox, encrypted_string, size).replace(b"\x00", b"").decode("utf-8")
            if decrypted_result and len(decrypted_result) > 1:
                entries.append(decrypted_result)

    if entries:
        c2s = []
        for item in entries:
            if item.count(".") == 3:
                c2s.append(item)

            if "http" in item:
                c2s.append(item)

            if item.count("-") == 4:
                cfg["Mutex"] = item

            if len(item) == 16 and is_hex(item):
                cfg["Encryption Key"] = item

        if c2s:
            cfg["C2"] = c2s

    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
