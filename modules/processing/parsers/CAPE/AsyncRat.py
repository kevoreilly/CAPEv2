# based on work of https://github.com/c3rb3ru5d3d53c/mwcfg-modules/blob/master/asyncrat/asyncrat.py

import base64
import logging
import string
import struct

import yara
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

log = logging.getLogger(__name__)

DESCRIPTION = "AsyncRat configuration parser."
AUTHOR = "Based on work of c3rb3ru5"

rule_source = """
rule asyncrat {
    meta:
        author      = "c3rb3ru5"
        author      = "JPCERT/CC Incident Response Group"
        description = "ASyncRAT"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        hash        = "330493a1ba3c3903040c9542e6348fab"
        type        = "malware.rat"
        created     = "2021-05-29"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $magic_cslr_0 = "BSJB"
        $salt         = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43
                         00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1           = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00
                         00}
        $b2           = {09 50 00 6F 00 6E 00 67 00 00}
        $s1           = "pastebin" ascii wide nocase
        $s2           = "pong" wide
        $s3           = "Stub.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        filesize < 2605056 and
        $magic_cslr_0 and
        ($salt and
         (2 of ($s*) or
         1 of ($b*))) or
        (all of ($b*) and
         2 of ($s*))
}
"""
yara_rules = yara.compile(source=rule_source)


def get_salt():
    return bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")


def decrypt(key, ciphertext):
    aes_key = PBKDF2(key, get_salt(), 32, 50000)
    cipher = AES.new(aes_key, AES.MODE_CBC, ciphertext[32 : 32 + 16])
    plaintext = cipher.decrypt(ciphertext[48:]).decode("ascii", "ignore").strip()
    return plaintext


def get_string(data, index):
    return data[index][1:].decode("utf-8", "ignore")


def decrypt_config_item_list(key, data, index):
    result = "".join(filter(lambda x: x in string.printable, decrypt(key, base64.b64decode(data[index][1:]))))
    if result == "null":
        return []
    return result.split(",")


def decrypt_config_item_printable(key, data, index):
    return "".join(filter(lambda x: x in string.printable, decrypt(key, base64.b64decode(data[index][1:]))))


def get_wide_string(data, index):
    return (data[index][1:] + b"\x00").decode("utf-16")


def extract_config(filebuf):
    config = {}
    addr = False

    matches = yara_rules.match(data=filebuf)
    if not matches:
        return config

    for match in matches[0].strings:
        if match[1] == "$magic_cslr_0":
            addr = match[0]

    strings_offset = struct.unpack("<I", filebuf[addr + 0x40 : addr + 0x44])[0]
    strings_size = struct.unpack("<I", filebuf[addr + 0x44 : addr + 0x48])[0]
    data = filebuf[addr + strings_offset : addr + strings_offset + strings_size]
    data = data.split(b"\x00\x00")
    key = base64.b64decode(get_string(data, 7))
    log.debug("extracted key: " + str(key))
    try:
        config = {
            "family": "asyncrat",
            "hosts": decrypt_config_item_list(key, data, 2),
            "ports": decrypt_config_item_list(key, data, 1),
            "version": decrypt_config_item_printable(key, data, 3),
            "install_folder": get_wide_string(data, 5),
            "install_file": get_wide_string(data, 6),
            "install": decrypt_config_item_printable(key, data, 4),
            "mutex": decrypt_config_item_printable(key, data, 8),
            "pastebin": decrypt(key, base64.b64decode(data[12][1:])).encode("ascii").replace(b"\x0f", b""),
        }
    except Exception as e:
        print(e)
        return {}

    if config["version"].startswith("0"):
        return config
    else:
        return {}


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    print(extract_config(data))
