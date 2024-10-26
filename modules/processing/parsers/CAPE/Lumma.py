import base64
import re

import pefile


def is_base64(s):
    pattern = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")
    if not s or len(s) < 1:
        return False
    else:
        return pattern.match(s)


def extract_strings(data, minchars):
    endlimit = b"8192"
    apat = b"([\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"})\x00"
    strings = [string.decode() for string in re.findall(apat, data)]
    return strings


def get_base64_strings(str_list):
    base64_strings = []
    for s in str_list:
        if is_base64(s):
            base64_strings.append(s)
    return base64_strings


def get_rdata(data):
    rdata = None
    pe = pefile.PE(data=data)
    section_idx = 0
    for section in pe.sections:
        if section.Name == b".rdata\x00\x00":
            rdata = pe.sections[section_idx].get_data()
            break
        section_idx += 1
    return rdata


def xor_data(data, key):
    decoded = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        if i >= key_len:
            break
        decoded.append(data[i] ^ key[i])
    return decoded


def contains_non_printable(byte_array):
    for byte in byte_array:
        if not chr(byte).isprintable():
            return True
    return False


def extract_config(data):
    config_dict = {"C2": []}

    try:
        lines = data.decode().split("\n")
        for line in lines:
            try:
                if "." in line and len(line) > 2:
                    if not contains_non_printable(line):
                        config_dict["C2"].append(line)
            except Exception:
                continue
    except Exception:
        pass

    # If no C2s with the old method,
    # try with newer version xor decoding
    if not config_dict["C2"]:
        try:
            rdata = get_rdata(data)
            strings = extract_strings(rdata, 44)
            base64_strings = get_base64_strings(strings)

            for base64_str in base64_strings:
                try:
                    decoded_bytes = base64.b64decode(base64_str, validate=True)
                    encoded_c2 = decoded_bytes[:32]
                    xor_key = decoded_bytes[32:]
                    decoded_c2 = xor_data(encoded_c2, xor_key)

                    if not contains_non_printable(decoded_c2):
                        config_dict["C2"].append(decoded_c2.decode())
                except Exception:
                    continue
        except Exception:
            return

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
