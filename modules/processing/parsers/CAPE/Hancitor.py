"""
    Hancitor config extractor
"""

import hashlib
import logging
import re
import struct

import pefile
from Cryptodome.Cipher import ARC4

DESCRIPTION = "Hancitor config extractor."
AUTHOR = "threathive, cccs-j"

log = logging.getLogger(__name__)


def getHashKey(key_data):
    # source: https://github.com/OALabs/Lab-Notes/blob/main/Hancitor/hancitor.ipynb
    m = hashlib.sha1()
    m.update(key_data)
    key = m.digest()[:5]
    return key


def get_key_config_data(filebuf, pe):
    # source: https://github.com/OALabs/Lab-Notes/blob/main/Hancitor/hancitor.ipynb
    RE_KEY = rb"\x6a(.)\x68(....)\x68\x00\x20\x00\x00"
    m = re.search(RE_KEY, filebuf)
    if not m:
        return
    key_len = struct.unpack("b", m.group(1))[0]
    key_address = struct.unpack("<I", m.group(2))[0]
    key_rva = key_address - pe.OPTIONAL_HEADER.ImageBase
    key_offset = pe.get_offset_from_rva(key_rva)
    key_data = filebuf[key_offset : key_offset + key_len]
    key = getHashKey(key_data)
    config_data = filebuf[key_offset + key_len : key_offset + key_len + 0x2000]
    return key, config_data


def extract_section(pe, name):
    for section in pe.sections:
        if name in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None


def extract_config(filebuf):
    cfg = {}
    try:
        pe = pefile.PE(data=filebuf, fast_load=False)
        DATA_SECTION = extract_section(pe, b".data")
        key = hashlib.sha1(DATA_SECTION[16:24]).digest()[:5]
        ENCRYPT_DATA = DATA_SECTION[24:2000]
        if DATA_SECTION[16:24] == b"\x00\x00\x00\x00\x00\x00\x00\x00":
            key, ENCRYPT_DATA = get_key_config_data(filebuf, pe)
        if not key:
            return
        DECRYPTED_DATA = ARC4.new(key).decrypt(ENCRYPT_DATA)
        build_id, controllers = list(filter(None, DECRYPTED_DATA.split(b"\x00")))
        cfg.setdefault("Build ID", build_id.decode())
        controllers = list(filter(None, controllers.split(b"|")))
        if controllers:
            cfg.setdefault("address", [url.decode() for url in controllers])
    except Exception as e:
        log.warning(e)

    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
