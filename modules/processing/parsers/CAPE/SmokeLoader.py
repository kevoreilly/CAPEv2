import logging
import struct
from contextlib import suppress

import yara
from Cryptodome.Cipher import ARC4

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

rule_source = """
rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        cape_type = "SmokeLoader Payload"
    strings:
        $rc4_decrypt64 = {41 8D 41 01 44 0F B6 C8 42 0F B6 [2] 41 8D 04 12 44 0F B6 D0 42 8A [2] 42 88 [2] 42 88 [2] 42 0F B6 [2] 03 CA 0F B6 C1 8A [2] 30 0F 48 FF C7 49 FF CB 75}
        $rc4_decrypt32 = {47 B9 FF 00 00 00 23 F9 8A 54 [2] 0F B6 C2 03 F0 23 F1 8A 44 [2] 88 44 [2] 88 54 [2] 0F B6 4C [2] 0F B6 C2 03 C8 81 E1 FF 00 00 00 8A 44 [2] 30 04 2B 43 3B 9C 24 [4] 72 C0}
        $fetch_c2_64 = {00 48 8D 05 [3] FF 48 8B CB 48 8B 14 D0 48 8B 5C 24 ?? 48 83 C4 20 5F E9}
        $fetch_c2_32 = {8B 96 [2] (00|01) 00 8B CE 5E 8B 14 95 [4] E9}
    condition:
        2 of them
}

"""

yara_rules = yara.compile(source=rule_source)


def rc4_decrypt(key, ciphertext):
    ARC4.key_size = range(1, 257)
    arc4 = ARC4.new(key)
    return arc4.decrypt(ciphertext)


def extract_config(filebuf):
    cfg = {}
    c2list = []
    c2list_offset = 0
    matches = yara_rules.match(data=filebuf)
    if not matches:
        return
    for match in matches:
        if match.rule != "SmokeLoader":
            continue
        for item in match.strings:
            for instance in item.instances:
                if "$fetch_c2_64" in item.identifier:
                    match_offset = (int(instance.offset) & 0xFFFF) + 4
                    try:
                        c2list_offset = (
                            struct.unpack("<I", filebuf[match_offset : match_offset + 4])[0] + match_offset + 4
                        ) & 0xFFFF
                    except Exception:
                        break
                    delta = 8
                if "$fetch_c2_32" in item.identifier:
                    match_offset = (int(instance.offset) & 0xFFFF) + 12
                    try:
                        c2list_offset = (struct.unpack("<I", filebuf[match_offset : match_offset + 4])[0]) & 0xFFFF
                    except Exception:
                        break
                    delta = 4
    if not c2list_offset:
        return
    while c2list_offset:
        with suppress(Exception):
            c2_offset = struct.unpack("<I", filebuf[c2list_offset : c2list_offset + 4])[0] & 0xFFFF
            line = filebuf[c2_offset:]
            size = struct.unpack("B", line[0:1])[0]
            if size and size < 100:
                c2list.append(rc4_decrypt(line[1:5], line[5 : size + 5]).decode())
        if not c2_offset or c2_offset < 0x100:
            break
        c2list_offset += delta
    if c2list != []:
        cfg["C2s"] = sorted(list(set(c2list)))
    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    logging.basicConfig()
    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
