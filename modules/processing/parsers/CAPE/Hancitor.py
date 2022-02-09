"""
    Hancitor config extractor
"""
import hashlib
import logging

import pefile
from Cryptodome.Cipher import ARC4

DESCRIPTION = "Hancitor config extractor."
AUTHOR = "threathive"

log = logging.getLogger(__name__)


def extract_config(filebuf):
    cfg = {}
    try:
        pe = pefile.PE(data=filebuf, fast_load=False)
        for i in pe.sections:
            if b".data" in i.Name:
                DATA_SECTION = i.get_data()
                key = hashlib.sha1(DATA_SECTION[16:24]).digest()[:5]
                ENCRYPT_DATA = DATA_SECTION[24:2000]
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

    with open(sys.argv[1], "rb") as f:
        file_data = f.read()
    print(extract_config(file_data))
