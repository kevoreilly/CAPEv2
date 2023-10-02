import base64
import binascii
import sys
from contextlib import suppress

from lib.cuckoo.common.integrations.strings import extract_strings


def decode(data):
    config = {}
    alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
    all_strings = extract_strings(data=data, on_demand=True, dedup=True)
    for strval in all_strings:
        with suppress(UnicodeDecodeError, binascii.Error):
            custom = strval.maketrans(alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
            strval = strval.translate(custom)
            padding = len(strval) % 4
            if padding:
                strval += alphabet[-1] * (4 - padding)
            decoded_str = base64.b64decode(strval).decode("utf-8")
            if decoded_str.startswith("0="):
                decoded_str = decoded_str.replace("0=", "port=", 1)
                config["other"] = [x for x in decoded_str.split("\r\n") if x.strip() != ""]
            elif decoded_str.startswith("http"):
                config["C2"] = [x for x in decoded_str.split("|") if x.strip() != ""]

    return config


def extract_config(data):
    return decode(data)


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as infile:
        t = decode(infile.read())
        print(t)
