# Author: RussianPanda
# https://github.com/RussianPanda95/Configuration_extractors/blob/main/vidar_config_extractor.py

import re
import struct
from contextlib import suppress

import pefile

# import requests


def extract_section(pe, name):
    for section in pe.sections:
        if name in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)


def within_section(addr, pe, name):
    for section in pe.sections:
        if name in section.Name:
            if section.VirtualAddress <= addr - pe.OPTIONAL_HEADER.ImageBase <= section.VirtualAddress + section.SizeOfRawData:
                return True
    return False


def extract_config(data):
    config_dict = {}
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=data, fast_load=False)
    if not pe:
        return

    # Look for the C2 in the ".rdata" section
    c2 = []
    rdata_data = extract_section(pe, b".rdata")
    if rdata_data:
        for m in re.finditer(rb"(https?://[\d\w\.:/?#&+=_-]+)", rdata_data):
            matches = m.group().decode().split("\0")[0]
            if len(matches) > 8:
                c2.append(matches)

    """ Leaking your IP, uncomment on your risks, 3rd is the proxy, not steam/t.me
    # Retrieve C2 from dead drops
    drops = []
    for url in c2:
        try:
            response = requests.get(url, timeout=3)
        except requests.Timeout:
            continue

        ip_pattern = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[^\|]*"
        ip_addresses = set(re.findall(ip_pattern, response.content.decode()))

        if len(ip_addresses) > 0:
            for ip in ip_addresses:
                drops.append(ip)

    for drop in drops:
        c2.append(drop)
    """
    config_dict["C2"] = c2

    text_data = extract_section(pe, b".text")

    # Find version based on opcodes
    pattern = rb"\x68(....)\x89\x45\xfc\x88\x06\xe8(....)\x83\xc4\x04|\x68(....)\x8b\xce\x89\x45\xfc\x88\x06"

    results = []
    for m in re.finditer(pattern, text_data):
        if m.group(1):
            str = struct.unpack("<I", m.group(1))[0]
        elif m.group(2):
            str = struct.unpack("<I", m.group(2))[0]
        else:
            str = struct.unpack("<I", m.group(3))[0]
        if within_section(str, pe, b".rdata"):
            with suppress(Exception):
                str = pe.get_string_at_rva(str - pe.OPTIONAL_HEADER.ImageBase, 50)
                results.append(str.decode())

    version = None
    for result in results:
        if "." in result and version is None:
            version = result
            config_dict["Version"] = version

    # Look for the version in ".rdata" if there are no xrefs. NOTE: this might produce FP results
    if not version:
        version = []
        for m in re.finditer(rb"\b\d+\.\d+\b", rdata_data):
            version.append(m.group().replace(b"\x00", b""))
        config_dict["Version"] = version[2].decode()

    return config_dict
