#!/usr/bin/env python
import hashlib
import string
import zlib
from base64 import b64decode
from io import StringIO
from zipfile import ZipFile

# Non Standard Imports
from Cryptodome.Cipher import AES, ARC4, XOR

# Helper Functions Go Here


def string_print(line):
    return [x for x in line if x in string.printable]


#### Ciphers ####
def decrypt_RC4(enckey, data):
    cipher = ARC4.new(enckey)
    return cipher.decrypt(data)


def decrypt_AES(enckey, data):
    cipher = AES.new(enckey)
    return cipher.decrypt(data)


def decrypt_XOR(enckey, data):
    cipher = XOR.new(enckey)
    return cipher.decrypt(data)


def parse_ek(key, drop):
    enc_key = key[:16]
    coded = drop
    drop_details = key[16:]
    decoded = decrypt_AES(enc_key, coded)
    for section in drop_details.split(","):
        print(b64decode(section).decode("hex"))
    return decoded


def parse_load(key, drop):
    raw_key = f"{key}ALSKEOPQLFKJDUSIKSJAUIE"
    enc_key = hashlib.sha256(raw_key).hexdigest()
    return decrypt_RC4(enc_key, drop)


def parse_stub(drop):
    keys = ("0kwi38djuie8oq89", "0B4wCrd5N2OxG93h")

    for key in keys:
        decoded = decrypt_AES(key, drop)
        if "META-INF" in decoded:
            print("Found Embedded Jar")
            return decoded
        if "Program" in decoded:
            print("Found Embedded EXE")
            return decoded


def parse_xor(key, drop):
    key2 = 'FYj&w3bd"m/kSZjD'
    decoded = decrypt_XOR(key2, drop)
    return zlib.decompress(decoded, 16 + zlib.MAX_WBITS)


# Jar Parser
def extract_config(raw_data):
    decoded = False
    jar_data = StringIO(raw_data)
    with ZipFile(jar_data, "r") as jar:
        files = jar.namelist()
        if "e" in files and "k" in files:
            print("Found EK Dropper")
            key = jar.read("k")
            drop = jar.read("e")
            decoded = parse_ek(key, drop)

        if "config.ini" in files and "password.ini" in files:
            print("Found LoadStub Dropper")
            key = jar.read("password.ini")
            drop = jar.read("config.ini")
            decoded = parse_load(key, drop)

        if "stub/stub.dll" in files:
            print("Found Stub Dropper")
            drop = jar.read("stub/stub.dll")
            decoded = parse_stub(drop)

        if "c.dat" in files:
            print("Found XOR Dropper")
            key_file = b64decode(jar.read("c.dat"))
            key_text = decrypt_XOR("\xdd", key_file)
            drop_file = key_text.split("\n", 2)[1]
            key = key_text.split("\n", 6)[5]
            print(key)
            decoded = parse_xor(key, jar.read(drop_file))

    if decoded:
        return decoded
    else:
        print("Unable to decode")
