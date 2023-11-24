import base64
import binascii
import re
import sys
import zlib
from contextlib import suppress

import pefile

alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
config_re = rb"[A-Za-z0-9+=]{8,}"
config_map = {
    "0": "c2_port",
    "1": "startup_persistence",
    "2": "rootkit",
    "3": "anti_vm",
    "4": "min_disk",
    "5": "check_disk",
    "6": "anti_analysis",
    "7": "min_ram",
    "8": "check_ram",
    "9": "check_xeon",
    "10": "internal_mutex",
    "11": "crypter_rawstub",
    "12": "crypter_dll",
    "13": "crypter_au3",
    "15": "crypto_key",
    "16": "c2_ping_interval",
    "17": "anti_debug",
    "19": "BSOD_protect",
    "21": "cryptominer_process_name",
    "22": "cryptominer_c2_port",
    "23": "cryptominer_username",
    "24": "cryptominer_start_c2_comms",
    "25": "cryptominer_start_delay",
    "27": "GUID_random_seed",
    "28": "verify_process_name",
}


def translate_string(strval, alphabet):
    custom = strval.maketrans(alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    strval = strval.translate(custom)
    padding = len(strval) % 4
    if padding:
        strval += alphabet[-1] * (4 - padding)
    return strval


def parse_config(data):
    config = {}
    for item in [x for x in data.decode("utf-8").split("\r\n") if x.strip() != ""]:
        k, v = item.split("=")
        try:
            config[config_map[k]] = v
        except KeyError:
            config[f"unknown_{k}"] = v

    return config


def decode(data):
    config = {}
    all_strings = re.findall(config_re, data)
    for strval in all_strings:
        with suppress(UnicodeDecodeError, binascii.Error, zlib.error):
            strval = translate_string(strval.decode("utf-8"), alphabet)
            decoded_str = base64.b64decode(strval)
            if decoded_str.startswith(b"http"):
                config["C2"] = [x for x in decoded_str.decode("utf-8").split("|") if x.strip() != ""]
            elif b"1=Yes" in decoded_str or b"1=No" in decoded_str:
                config.update(parse_config(decoded_str))
            else:
                decoded_str = zlib.decompress(decoded_str)
                if b"1=Yes" in decoded_str or b"1=No" in decoded_str:
                    config.update(parse_config(decoded_str))
    return config


def extract_config(data):
    with suppress(pefile.PEFormatError):
        pe = pefile.PE(data=data)
        for section in pe.sections:
            if b"CODE" in section.Name:
                return decode(section.get_data())
    return ""


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as infile:
        t = extract_config(infile.read())
        print(t)
