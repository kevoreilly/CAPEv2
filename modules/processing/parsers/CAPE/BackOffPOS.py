# coding=UTF-8

from __future__ import absolute_import
from __future__ import print_function
import sys
import pefile
from struct import unpack_from
from sys import argv
from binascii import hexlify
from hashlib import md5
from Crypto.Cipher import ARC4


header_ptrn = b"Content-Type: application/x-www-form-urlencoded"


def RC4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def extract_config(data):
    config_data = dict()
    urls = []
    pe = pefile.PE(data=data)
    for section in pe.sections:
        if b".data" in section.Name:
            data = section.get_data()
            cfg_start = data.find(header_ptrn)
            if cfg_start and cfg_start != -1:
                start_offset = cfg_start + len(header_ptrn) + 1
                rc4_seed = bytes(bytearray(unpack_from(">8B", data, offset=start_offset)))
                config_data["RC4Seed"] = hexlify(rc4_seed)
                key = md5(rc4_seed).digest()[:5]
                config_data["EncryptionKey"] = hexlify(key)
                enc_data = bytes(bytearray(unpack_from(">8192B", data, offset=start_offset + 8)))
                dec_data = RC4(key, enc_data)
                config_data["Build"] = dec_data[:16].strip("\x00")
                for url in dec_data[16:].split("|"):
                    urls.append(url.strip("\x00"))
                config_data["URLs"] = urls
                config_data["Version"] = unpack_from(">5s", data, offset=start_offset + 16 + 8192)[0]
                print("")
            else:
                return None

    return config_data


def config(task_info, data):
    return extract_config(data)


if __name__ == "__main__":
    filename = argv[1]
    with open(filename, "rb") as infile:
        t = config(0, infile.read())
    print(t)
