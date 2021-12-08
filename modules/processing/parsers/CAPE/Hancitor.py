"""
    Hancitor config extractor
"""
import pefile
import hashlib
from Crypto.Cipher import ARC4
import logging

log = logging.getLogger(__name__)


def config(filebuf):
    DESCRIPTION = "Hancitor config extractor."
    AUTHOR = "threathive"
    cfg = dict()
    try:
        pe = pefile.PE(data=filebuf, fast_load=False)
        for i in pe.sections:
            if b".data" in i.Name:
                DATA_SECTION = i.get_data()
                RC4_KEY = hashlib.sha1(DATA_SECTION[16:24]).digest()[:5]
                ENCRYPT_DATA = DATA_SECTION[24:2000]
                DECRYPTED_DATA = ARC4.new(RC4_KEY).decrypt(ENCRYPT_DATA)
                build_id, controllers = list(filter(None, DECRYPTED_DATA.split(b"\x00")))
                cfg.setdefault("Build ID", build_id)
                controllers = list(filter(None, controllers.split(b"|")))
                if controllers:
                    cfg.setdefault("address", controllers)
    except Exception as e:
        log.warning(e)

    return cfg


if __name__ == "__main__":
    import sys

    file_data = open(sys.argv[1], "rb").read()
    print(config(file_data))
