# https://research.openanalysis.net/pikabot/yara/config/loader/2023/02/26/pikabot.html

import base64
import re
import sys
from contextlib import suppress

import pefile


class PikaException(Exception):
    pass


def xor(data, key):
    out = []
    for c in data:
        out.append(c ^ key)
    return bytes(out)


def wide_finder(data):
    str_end = len(data)
    for i in range(0, len(data) - 1, 2):
        if not chr(data[i]).isascii():
            str_end = i
            break
        if data[i + 1] != 0:
            str_end = i
            break
    return data[:str_end]


def get_url(ps_string):
    out = None
    m = re.search(r"http[^ ]*", ps_string)
    if m:
        out = m.group()
    return out


def extract_config(filebuf):
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=filebuf, fast_load=False)

    if not pe:
        return

    section_data = None
    for s in pe.sections:
        if s.Name.startswith(b".rdata"):
            section_data = s.get_data()
            break

    if not section_data:
        return

    big_null = section_data.find(b"\x00" * 30)
    section_data = section_data[:big_null]
    out = None

    for i in range(1, 0xFF):
        egg = bytes([i]) * 16
        if egg in section_data:
            test_out = xor(section_data, i)
            # This might break if the extra crud on the end of the blob is not b64 friendly
            try:
                test_out_ptxt = base64.b64decode(test_out)
            except Exception:
                continue
            if "http".encode("utf-16le") in test_out_ptxt:
                out = wide_finder(test_out_ptxt).decode("utf-16le")

    if not out:
        return

    url = get_url(out)
    return {"C2": [url], "PowerShell": out}


if __name__ == "__main__":
    print(extract_config(sys.argv[1]))
