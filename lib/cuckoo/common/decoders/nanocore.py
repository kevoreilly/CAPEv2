# Copyright (C) 2014-2015 Kevin Breen (http://techanarchy.net), Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
import zlib
import string
import pefile
import logging
from struct import unpack, unpack_from
import uuid
import datetime
from Crypto.Cipher import DES, AES

# we use some features re2 doesn't support
import re

log = logging.getLogger(__name__)

# Helper Functions Go Here


def derive_key(guid, coded_key):
    try:
        from pbkdf2 import PBKDF2
    except:
        log.error("[!] Unable to derive a key. requires 'sudo pip3 install pbkdf2'")
        return None

    generator = PBKDF2(guid, guid, 8)
    aes_iv = generator.read(16)
    aes_key = generator.read(16)
    derived_key = decrypt_aes(aes_key, aes_iv, coded_key)
    return derived_key


def decrypt_v3(coded_config, key):
    data = coded_config[24:]
    raw_config = decrypt_des(key[:8], data)
    # if the config is over a certain size it is compressed. Indicated by a non Null byte
    if raw_config[1] == "\x00":
        return parse_config(raw_config)
    else:
        # remove the string lengths and deflate the remainder of the stream
        deflate_config = deflate_contents(raw_config)
        # with open('nano_2.res', 'wb') as out:
        #    out.write(deflate_config)
        return parse_config(deflate_config)


def decrypt_v2(coded_config):
    key = coded_config[4:12]
    data = coded_config[16:]
    raw_config = decrypt_des(key, data)
    # if the config is over a certain size it is compressed. Indicated by a non Null byte
    if raw_config[1] == "\x00":
        return parse_config(raw_config)
    else:
        # remove the string lengths and deflate the remainder of the stream
        deflate_config = deflate_contents(raw_config)
        return parse_config(deflate_config)


def decrypt_v1(coded_config):
    key = "\x01\x03\x05\x08\x0d\x15\x22\x37"
    data = coded_config[1:]
    new_data = decrypt_des(key, data)
    if new_data[0] != "\x00":
        deflate_config = deflate_contents(new_data)
        return parse_config(deflate_config)


def deflate_contents(data):
    new_data = data[5:]
    return zlib.decompress(new_data, -15)


# Returns only printable chars
def string_print(line):
    try:
        return "".join((char for char in line if 31 < ord(char) < 127))
    except:
        return line


def peek_code(buf, idx):
    ret = None
    try:
        ret = unpack_from("B", buf[idx:])[0]
    except:
        pass
    return ret


def get_val(buf, idx):
    code = unpack_from("B", buf[idx:])[0]
    idx += 1
    if code == 7:
        theval = unpack_from("<I", buf[idx:])[0]
        idx += 4
    elif code == 12:
        strlen = unpack_from("B", buf[idx:])[0]
        idx += 1
        theval = buf[idx : idx + strlen]
        idx += strlen
    elif code == 0:
        theval = unpack_from("?", buf[idx:])[0]
        idx += 1
    elif code == 16:
        thetime = unpack_from("<Q", buf[idx:])[0]
        idx += 8
        # convert from .NET DateTime to Python datetime (mask off the DateTimeKind, which is set to UTC in NanoCore)
        # magic value is the number of 100ns increments since start of Gregorian calendar up to beginning of unix epoch time
        theval = str(datetime.datetime.utcfromtimestamp(((thetime & 0x0FFFFFFFFFFFFFFF) - 0x089F7FF5F7B58000) / 10000000)) + " UTC"
    elif code == 21:
        # version
        strlen = unpack_from("B", buf[idx:])[0]
        idx += 1
        theval = buf[idx : idx + strlen]
        idx += strlen
    elif code == 18:
        # guid
        thestr = buf[idx : idx + 16]
        # we're not going to bother using the guid for anything but the mutex name, so just adjust it here
        theval = "Global\{" + str(uuid.UUID(bytes_le=thestr)) + "}"
        idx += 16
    elif code == 15:
        # ushort
        theval = unpack_from("<H", buf[idx:])[0]
        idx += 2
    elif code == 2:
        # binary blob of X bytes
        theval = unpack_from("<I", buf[idx:])[0]
        idx += 4 + theval
        theval = "binary"
    else:
        # could easily implement more codes, but this will do for now
        log.warn("Unimplemented NanoCore code: %d, report to brad.spengler@optiv.com", code)
        return None, None
    return idx, code, theval


# returns pretty config
def parse_config(raw_config):
    buf = raw_config[3:]
    idx = 0
    config_dict = {}
    datestr = ""
    lastkey = ""
    while peek_code(buf, idx) == 7:
        idx, code, numelem = get_val(buf, idx)
        if peek_code(buf, idx) != 12:
            # we could also easily pull out the client interface and plugin DLL, but let's just
            # extract the build date and plugin name
            for i in range(numelem):
                idx, code, theval = get_val(buf, idx)
                if code == 12:
                    config_dict[theval] = "Build Date: " + datestr
                elif code == 16:
                    datestr = theval
        else:
            for i in range(numelem):
                idx, code, theval = get_val(buf, idx)
                if not (i % 2):
                    lastkey = theval
                else:
                    config_dict[lastkey] = theval
    return config_dict


# This gets the encoded config from a stub
def get_codedconfig(pe):
    coded_config = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) == "RC_DATA" or "RCData":
            new_dirs = entry.directory
            for res in new_dirs.entries:
                data_rva = res.directory.entries[0].data.struct.OffsetToData
                size = res.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                coded_config = data
                # Icons can get in the way.
                if coded_config.startswith("\x28\x00\x00"):
                    break
                return coded_config


def decrypt_des(key, data):
    iv = key
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)


def decrypt_aes(key, iv, data):
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode, IV=iv)
    return cipher.decrypt(data)


def extract_config(pe):
    try:
        coded_config = get_codedconfig(pe)
        if coded_config[0:4] == "\x08\x00\x00\x00":
            # print "    [-] Found version 1.1x"
            config_dict = decrypt_v2(coded_config)

        elif coded_config[0:4] == "\x10\x00\x00\x00":
            # print "    [-] Found Version 2.x"
            # we need to derive a key from the assembly guid
            guid = re.search("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", pe.__data__).group()
            guid = uuid.UUID(guid).bytes_le
            encrypted_key = coded_config[4:20]
            # rfc2898 derive bytes
            derived_key = derive_key(guid, encrypted_key)
            config_dict = decrypt_v3(coded_config, derived_key)
        else:
            # print "    [-] Found Version 1.0x"
            config_dict = decrypt_v1(coded_config)
        return config_dict
    except:
        return
