import struct
from contextlib import suppress

import pefile
import yara

MAX_STRING_SIZE = 100

# Hash = 619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470

RULE_SOURCE = """rule StealC
{
    meta:
        author = "Yung Binary"
        hash = "619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470"
    strings:
        $decode_1 = {
            6A ??
            68 ?? ?? ?? ??
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            83 C4 0C
            A3 ?? ?? ?? ??
        }

    condition:
        $decode_1
}"""


def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield instance.offset


def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i])
    return decoded


def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


def extract_config(data):
    config_dict = {}

    # Attempt to extract via old method
    try:
        domain = ""
        uri = ""
        lines = data.decode().split("\n")
        for line in lines:
            if line.startswith("http") and "://" in line:
                domain = line
            if line.startswith("/") and line[-4] == ".":
                uri = line
        if domain and uri:
            config_dict.setdefault("C2", []).append(f"{domain}{uri}")
    except Exception:
        pass

    # Try with new method
    if not config_dict.get("C2"):
        with suppress(Exception):
            # config_dict["Strings"] = []
            pe = pefile.PE(data=data, fast_load=False)
            image_base = pe.OPTIONAL_HEADER.ImageBase

            for str_decode_offset in yara_scan(data):
                str_size = int(data[str_decode_offset + 1])
                # Ignore size 0 strings
                if not str_size:
                    continue

                key_rva = data[str_decode_offset + 3 : str_decode_offset + 7]
                encoded_str_rva = data[str_decode_offset + 8 : str_decode_offset + 12]
                # dword_rva = data[str_decode_offset + 21 : str_decode_offset + 25]

                key_offset = pe.get_offset_from_rva(struct.unpack("i", key_rva)[0] - image_base)
                encoded_str_offset = pe.get_offset_from_rva(struct.unpack("i", encoded_str_rva)[0] - image_base)
                # dword_offset = hex(struct.unpack("i", dword_rva)[0])[2:]

                key = string_from_offset(data, key_offset)
                encoded_str = string_from_offset(data, encoded_str_offset)

                decoded_str = xor_data(encoded_str, key).decode()
                if ("http://" in decoded_str or "https://" in decoded_str) and len(decoded_str) > 11:
                    config_dict.setdefault("C2", []).append(decoded_str)
                # else:
                #    config_dict["Strings"].append({f"dword_{dword_offset}" : decoded_str})

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
