import base64
import logging
import re
import struct
from contextlib import suppress
from io import BytesIO

import pefile
import yara

rule_source = """
rule PikaBot
{
    meta:
        author = "enzo"
        description = "Pikabot config extraction"
        packed = ""
    strings:
        $config = {C7 44 24 [3] 00 00 C7 44 24 [4] 00 89 [1-4] ?? E8 [4] 31 C0 C7 44 24 [3] 00 00 89 44 24 ?? C7 04 24 [4] E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
"""

yara_rules = yara.compile(source=rule_source)

log = logging.getLogger(__name__)


class PikaException(Exception):
    pass


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)


def xor(data, key):
    return bytes([c ^ key for c in data])


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


def get_wchar_string(data, length):
    data = data.read(length)
    return data.decode("utf-16-le")


def get_strings(data, count):
    w_strings = []
    for _ in range(count):
        length = struct.unpack("I", data.read(4))[0]
        w_string = get_wchar_string(data, length)
        w_strings.append(w_string)
    return w_strings


def get_c2s(data, count):
    c2_list = []
    for _ in range(count):
        c2_size = struct.unpack("I", data.read(4))[0]
        c2 = get_wchar_string(data, c2_size)
        port, val1, val2 = struct.unpack("III", data.read(12))
        c2_list.append(f"{c2}:{port}")
    return c2_list


def get_config(input_data):
    data = BytesIO(input_data)
    rounds, config_size, _, version_size = struct.unpack("=IIBI", data.read(13))
    version = get_wchar_string(data, version_size)
    campaign_size = struct.unpack("I", data.read(4))[0]
    campaign_name = get_wchar_string(data, campaign_size)
    registry_key_size = struct.unpack("I", data.read(4))[0]
    registry_key = get_wchar_string(data, registry_key_size)
    user_agent_size = struct.unpack("I", data.read(4))[0]
    user_agent = get_wchar_string(data, user_agent_size)
    number_of_http_headers = struct.unpack("I", data.read(4))[0]
    get_strings(data, number_of_http_headers)
    number_of_api_cmds = struct.unpack("I", data.read(4))[0]
    get_strings(data, number_of_api_cmds)
    number_of_c2s = struct.unpack("I", data.read(4))[0]
    c2s = get_c2s(data, number_of_c2s)

    return {
        "Version": version,
        "Campaign Name": campaign_name,
        "Registry Key": registry_key,
        "User Agent": user_agent,
        # "request_headers": request_headers,
        # "api_cmds": api_cmds,
        "C2s": c2s,
    }


def extract_config(filebuf):
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=filebuf, fast_load=False)

    if not pe:
        return

    r_data = None
    data = None

    r_data_sections = [s for s in pe.sections if s.Name.find(b".rdata") != -1]
    if r_data_sections:
        r_data = r_data_sections[0].get_data()

    data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
    if data_sections:
        data = data_sections[0].get_data()

    if r_data:
        big_null = r_data.find(b"\x00" * 30)
        r_data = r_data[:big_null]
        out = None

        for i in range(1, 0xFF):
            egg = bytes([i]) * 16
            if egg in r_data:
                test_out = xor(r_data, i)
                # This might break if the extra crud on the end of the blob is not b64 friendly
                try:
                    test_out_ptxt = base64.b64decode(test_out)
                except Exception:
                    continue
                if "http".encode("utf-16le") in test_out_ptxt:
                    out = wide_finder(test_out_ptxt).decode("utf-16le")
        if out:
            url = get_url(out)
            return {"C2": [url], "PowerShell": out}

    if data:
        yara_hit = yara_scan(filebuf)
        cfg_va = None
        cfg_offset = None
        cfg_length = 0

        for hit in yara_hit:
            if hit.rule == "PikaBot":
                for item in hit.strings:
                    if "$config" == item.identifier:
                        offset = item.instances[0].offset
                        cfg_va = filebuf[offset + 12 : offset + 16]
                with suppress(Exception):
                    pe = pefile.PE(data=filebuf, fast_load=True)
                    cfg_offset = pe.get_offset_from_rva(struct.unpack("I", cfg_va)[0] - pe.OPTIONAL_HEADER.ImageBase)
                    cfg_length = struct.unpack("H", filebuf[offset + 4 : offset + 6])[0]
                    break

        if cfg_offset:
            data = filebuf[cfg_offset : cfg_offset + cfg_length]
            if data[4:8] == b"\x00\x00\x00\x00":
                return
            with suppress(Exception):
                config = get_config(data)
                return config


if __name__ == "__main__":
    import sys

    print(extract_config(sys.argv[1]))
