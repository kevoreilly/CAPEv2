#!/usr/bin/env python
#
# LICENSE
# the GNU General Public License version 2
#
# Credit to JPCERT - this is derived from https://github.com/JPCERTCC/aa-tools/blob/master/tscookie_decode.py

import collections
import re
import sys
from struct import unpack, unpack_from

import pefile

# Resource pattern
RESOURCE_PATTERNS = [
    re.compile("\x50\x68(....)\x68(.)\x00\x00\x00(.)\xE8", re.DOTALL),
    re.compile("(.)\x68(...)\x00\x68(.)\x00\x00\x00\x6A\x00\xE8(....)\x83(..)\xC3", re.DOTALL),
    re.compile("\x04(.....)\x68(.)\x00\x00\x00\x6A\x00\xE8", re.DOTALL),
    re.compile("\x56\xBE(....)\x56\x68(.)\x00\x00\x00\x6A\x00\xE8", re.DOTALL),
    re.compile("\x53\x68(....)\x6A(.)\x56\xFF", re.DOTALL),
]

# RC4 key pattern
RC4_KEY_PATTERNS = [
    re.compile("\x80\x68\x80\x00\x00\x00\x50\xC7\x40", re.DOTALL),
    re.compile("\x80\x68\x80\x00\x00\x00(...)\x50\x52\x53\xC7\x40", re.DOTALL),
]
RC4_KEY_LENGTH = 0x80

# Config pattern
CONFIG_PATTERNS = [
    re.compile("\xC3\x90\x68(....)\xE8(....)\x59\x6A\x01\x58\xC3", re.DOTALL),
    re.compile("\x6A\x04\x68(....)\x8D(.....)\x56\x50\xE8", re.DOTALL),
]
CONFIG_SIZE = 0x8D4


# RC4
def rc4(data, key):
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return "".join(out)


# helper function for formatting string
def __format_string(data):
    return data.split("\x00", 1)[0]


# Parse config
def parse_config(config):
    config_dict = collections.OrderedDict()
    for i in range(4):
        if config[0x10 + 0x100 * i] != "\x00":
            config_dict[f"Server name #{i + 1}"] = __format_string(
                unpack_from("<240s", config, 0x10 + 0x100 * i)[0].decode("utf-16")
            )
            config_dict[f"Main port #{i + 1}"] = unpack_from("<H", config, 0x4 + 0x100 * i)[0]
            config_dict[f"Backup port #{i + 1}"] = unpack_from("<H", config, 0x8 + 0x100 * i)[0]
    if config[0x400] != "\x00":
        config_dict["Proxy server"] = __format_string(unpack_from("<128s", config, 0x400)[0].decode("utf-16"))
        config_dict["Proxy port"] = unpack_from("<H", config, 0x480)[0]
    config_dict["ID"] = __format_string(unpack_from("<256s", config, 0x500)[0].decode("utf-16"))
    config_dict["Key"] = f"0x{unpack_from('>I', config, 0x604)[0]:X}"
    config_dict["Sleep time"] = unpack_from("<H", config, 0x89C)[0]
    return config_dict


# Decode resource
def decode_resource(rc_data, key_end, fname):
    try:
        enc_data = rc_data[:-RC4_KEY_LENGTH]
        rc4key = rc_data[-RC4_KEY_LENGTH:-4] + key_end
        dec_data = rc4(enc_data, rc4key)
        open(fname, "wb").write(dec_data)
    except Exception:
        return
    return dec_data


# Find RC4 key
def load_rc4key(data):
    for pattern in RC4_KEY_PATTERNS:
        mk = re.search(pattern, data)
        key_end = ""
        if mk:
            key_end = data[mk.end() + 1 : mk.end() + 5]
            break
    return key_end


# Find and load resource
def load_resource(pe, data):
    for pattern in RESOURCE_PATTERNS:
        mr = re.search(pattern, data)
        if mr:
            try:
                (resource_name_rva,) = unpack("=I", data[mr.start() + 2 : mr.start() + 6])
                rn_addr = pe.get_physical_by_rva(resource_name_rva - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase)
                resource_name = data[rn_addr : rn_addr + 4]
                resource_id = ord(unpack("c", data[mr.start() + 7])[0])
                if resource_id > 200:
                    resource_id = ord(unpack("c", data[mr.start() + 8])[0])
                if resource_id == 104:
                    resource_id = ord(unpack("c", data[mr.start() + 21])[0])
                break
            except Exception:
                return
    if not mr:
        sys.exit("[!] Resource id not found")

    for idx in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(idx.name) in str(resource_name):
            for entry in idx.directory.entries:
                if entry.id == resource_id:
                    try:
                        data_rva = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        rc_data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                    except Exception:
                        return

    return rc_data


def extract_config(data):
    try:
        dll = pefile.PE(data=data)
    except Exception:
        return None

    for pattern in CONFIG_PATTERNS:
        mc = re.search(pattern, data)
        if mc:
            try:
                (config_rva,) = unpack("=I", data[mc.start() + 3 : mc.start() + 7])
                config_addr = dll.get_physical_by_rva(config_rva - dll.NT_HEADERS.OPTIONAL_HEADER.ImageBase)
                enc_config_data = data[config_addr : config_addr + CONFIG_SIZE]
            except Exception:
                return

    for pattern in RESOURCE_PATTERNS:
        mr2 = re.search(pattern, data)

    if mr2:
        rc2_data = load_resource(dll, data)
        key_end = load_rc4key(data)
        decode_resource(rc2_data, key_end, "TSCookie.2nd.decode")

    try:
        enc_config = enc_config_data[4:]
        rc4key = enc_config_data[:4]
        config = rc4(enc_config, rc4key)
    except Exception:
        return

    return parse_config(config)
