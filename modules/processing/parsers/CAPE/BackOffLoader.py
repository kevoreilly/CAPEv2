from binascii import hexlify
from hashlib import md5
from struct import unpack_from
from sys import argv

import pefile
from Cryptodome.Cipher import ARC4

CFG_START = "1020304050607080"


def RC4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def extract_config(data):
    config_data = {}
    pe = pefile.PE(data=data)
    for section in pe.sections:
        if b".data" in section.Name:
            data = section.get_data()
            if CFG_START != hexlify(unpack_from(">8s", data, offset=8)[0]):
                return None
            rc4_seed = bytes(bytearray(unpack_from(">8B", data, offset=24)))
            key = md5(rc4_seed).digest()[:5]
            enc_data = bytes(bytearray(unpack_from(">8192B", data, offset=32)))
            dec_data = RC4(key, enc_data)
            config_data = {
                "Version": unpack_from(">5s", data, offset=16)[0],
                "RC4Seed": hexlify(rc4_seed),
                "EncryptionKey": hexlify(key),
                "OnDiskConfigKey": unpack_from("20s", data, offset=8224)[0],
                "Build": dec_data[:16].strip("\x00"),
                "URLs": [url.strip("\x00") for url in dec_data[16:].split("|")],
            }
    return config_data


if __name__ == "__main__":
    filename = argv[1]
    with open(filename, "r") as infile:
        t = extract_config(infile.read())
    print(t)
