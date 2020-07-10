# coding=UTF-8

from __future__ import absolute_import
from __future__ import print_function
import pefile
from struct import unpack_from
from sys import argv
from binascii import hexlify
from hashlib import md5
from Crypto.Cipher import ARC4

CFG_START = "1020304050607080"


def RC4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def extract_config(data):
    config_data = dict()
    urls = []
    pe = pefile.PE(data=data)
    type(pe)
    for section in pe.sections:
        if ".data" in section.Name:
            data = section.get_data()
            if CFG_START == hexlify(unpack_from(">8s", data, offset=8)[0]):
                config_data["Version"] = unpack_from(">5s", data, offset=16)[0]
                rc4_seed = bytes(bytearray(unpack_from(">8B", data, offset=24)))
                config_data["RC4Seed"] = hexlify(rc4_seed)
                key = md5(rc4_seed).digest()[:5]
                config_data["EncryptionKey"] = hexlify(key)
                enc_data = bytes(bytearray(unpack_from(">8192B", data, offset=32)))
                dec_data = RC4(key, enc_data)
                config_data["OnDiskConfigKey"] = unpack_from("20s", data, offset=8224)[0]
                config_data["Build"] = dec_data[:16].strip("\x00")
                for url in dec_data[16:].split("|"):
                    urls.append(url.strip("\x00"))
                config_data["URLs"] = urls
                print("")
            else:
                return None

    return config_data


def config(task_info, data):
    return extract_config(data)


if __name__ == "__main__":
    filename = argv[1]
    with open(filename, "r") as infile:
        t = config(0, infile.read())
    print(t)
