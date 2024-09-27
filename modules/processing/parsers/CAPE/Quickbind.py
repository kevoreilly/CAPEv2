import logging
import re
import struct
from contextlib import suppress

import pefile
from Cryptodome.Cipher import ARC4

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def is_hex(hex_string):
    if len(hex_string) % 2 != 0:
        return False

    if not re.fullmatch(r"[0-9a-fA-F]+", hex_string):
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
            decrypted_result = ARC4.new(key).decrypt(encrypted_string).replace(b"\x00", b"").decode("utf-8")
            if decrypted_result and len(decrypted_result) > 1:
                entries.append(decrypted_result)

    if entries:
        c2s = []
        mutexes = []

        for item in entries:
            if item.count(".") == 3 and re.fullmatch(r"\d+", item.replace(".", "")):
                c2s.append(item)

            elif "http" in item:
                c2s.append(item)

            elif item.count("-") == 4:
                mutexes.append(item)

            elif len(item) in [16] and is_hex(item):
                cfg["Encryption Key"] = item

        if c2s:
            cfg["C2"] = c2s

        if mutexes:
            cfg["Mutex"] = list(set(mutexes))

    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
