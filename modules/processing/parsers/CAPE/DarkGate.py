import base64
import binascii
import sys

import pefile

from lib.cuckoo.common.integrations.strings import extract_strings


def decode(data):
    config = {}
    alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
    all_strings = extract_strings(data=data, on_demand=True, dedup=True)
    for strval in all_strings:
        try:
            custom = strval.maketrans(alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            strval = strval.translate(custom)
            padding = len(strval) % 4
            if padding:
                strval += alphabet[-1] * (4 - padding)
            decoded_bytes = base64.b64decode(strval)
            decoded_str = decoded_bytes.decode("utf-8")
            if decoded_str.startswith("0="):
                config["other"] = decoded_str.split("\r\n")
            elif decoded_str.startswith("http"):
                config["C2"] = decoded_str
        except (UnicodeDecodeError, binascii.Error):
            pass

    return config


def extract_config(data):
    pe = pefile.PE(data=data)
    for section in pe.sections:
        if b"CODE" in section.Name:
            data = section.get_data()
            return decode(data)


if __name__ == "__main__":
    filename = sys.argv[1]
    with open(filename, "rb") as infile:
        t = extract_config(infile.read())
    print(t)
