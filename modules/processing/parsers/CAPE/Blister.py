# BLISTER Configuration Extractor
# Python script to extract the configuration and payload from BLISTER samples.
# Author: soolidsnake (Elastic)
# https://elastic.github.io/security-research/tools/blister-config-extractor/
#
# Modified for CAPE by kevoreilly

import binascii
import json
import logging
import os
import sys
from optparse import OptionParser
from pathlib import Path
from struct import pack, unpack

import pefile
import yara

from lib.cuckoo.common.integrations.lznt1 import lznt1

log = logging.getLogger(__name__)


# https://github.com/Robin-Pwner/Rabbit-Cipher/
def ROTL8(v, n):
    return ((v << n) & 0xFF) | ((v >> (8 - n)) & 0xFF)


def ROTL16(v, n):
    return ((v << n) & 0xFFFF) | ((v >> (16 - n)) & 0xFFFF)


def ROTL32(v, n):
    return ((v << n) & 0xFFFFFFFF) | ((v >> (32 - n)) & 0xFFFFFFFF)


def ROTL64(v, n):
    return ((v << n) & 0xFFFFFFFFFFFFFFFF) | ((v >> (64 - n)) & 0xFFFFFFFFFFFFFFFF)


def ROTR8(v, n):
    return ROTL8(v, 8 - n)


def ROTR16(v, n):
    return ROTL16(v, 16 - n)


def ROTR32(v, n):
    return ROTL32(v, 32 - n)


def ROTR64(v, n):
    return ROTL64(v, 64 - n)


def SWAP32(v):
    return (ROTL32(v, 8) & 0x00FF00FF) | (ROTL32(v, 24) & 0xFF00FF00)


class Rabbit_state(object):
    def __init__(self):
        self.x = [0] * 8
        self.c = [0] * 8
        self.carry = 0


class Rabbit_ctx(object):
    def __init__(self):
        self.m = Rabbit_state()
        self.w = Rabbit_state()


class Rabbit(object):
    def __init__(self, key, iv):
        self.ctx = Rabbit_ctx()
        self.set_iv(iv)
        self.set_key(key)
        if len(iv):
            pass

    def g_func(self, x):
        x = x & 0xFFFFFFFF
        x = (x * x) & 0xFFFFFFFFFFFFFFFF
        result = (x >> 32) ^ (x & 0xFFFFFFFF)
        return result

    def set_key(self, key):
        # generate four subkeys
        key0 = unpack("<I", key[0:4])[0]
        key1 = unpack("<I", key[4:8])[0]
        key2 = unpack("<I", key[8:12])[0]
        key3 = unpack("<I", key[12:16])[0]
        s = self.ctx.m
        # generate initial state variables
        s.x[0] = key0
        s.x[2] = key1
        s.x[4] = key2
        s.x[6] = key3
        s.x[1] = ((key3 << 16) & 0xFFFFFFFF) | ((key2 >> 16) & 0xFFFF)
        s.x[3] = ((key0 << 16) & 0xFFFFFFFF) | ((key3 >> 16) & 0xFFFF)
        s.x[5] = ((key1 << 16) & 0xFFFFFFFF) | ((key0 >> 16) & 0xFFFF)
        s.x[7] = ((key2 << 16) & 0xFFFFFFFF) | ((key1 >> 16) & 0xFFFF)
        # generate initial counter values
        s.c[0] = ROTL32(key2, 16)
        s.c[2] = ROTL32(key3, 16)
        s.c[4] = ROTL32(key0, 16)
        s.c[6] = ROTL32(key1, 16)
        s.c[1] = (key0 & 0xFFFF0000) | (key1 & 0xFFFF)
        s.c[3] = (key1 & 0xFFFF0000) | (key2 & 0xFFFF)
        s.c[5] = (key2 & 0xFFFF0000) | (key3 & 0xFFFF)
        s.c[7] = (key3 & 0xFFFF0000) | (key0 & 0xFFFF)
        s.carry = 0

        # Iterate system four times
        for i in range(4):
            self.next_state(self.ctx.m)

        for i in range(8):
            # modify the counters
            self.ctx.m.c[i] ^= self.ctx.m.x[(i + 4) & 7]
        # Copy master instance to work instance
        self.ctx.w = self.copy_state(self.ctx.m)

    def copy_state(self, state):
        n = Rabbit_state()
        n.carry = state.carry

        for i, j in enumerate(state.x):
            n.x[i] = j
        for i, j in enumerate(state.c):
            n.c[i] = j
        return n

    def set_iv(self, iv):
        # generate four subvectors
        v = [0] * 4
        v[0] = unpack("<I", iv[0:4])[0]
        v[2] = unpack("<I", iv[4:8])[0]
        v[1] = (v[0] >> 16) | (v[2] & 0xFFFF0000)
        v[3] = ((v[2] << 16) | (v[0] & 0x0000FFFF)) & 0xFFFFFFFF
        # Modify work's counter values
        for i in range(8):
            self.ctx.w.c[i] = self.ctx.m.c[i] ^ v[i & 3]
        # Copy state variables but not carry flag
        tmp = []

        for cc in self.ctx.m.x:
            tmp += [cc]
        self.ctx.w.x = tmp

        # Iterate system four times
        for i in range(4):
            self.next_state(self.ctx.w)

    def next_state(self, state):
        g = [0] * 8
        x = [0x4D34D34D, 0xD34D34D3, 0x34D34D34]
        # calculate new counter values
        for i in range(8):
            tmp = state.c[i]
            state.c[i] = (state.c[i] + x[i % 3] + state.carry) & 0xFFFFFFFF
            state.carry = state.c[i] < tmp
        # calculate the g-values
        for i in range(8):
            g[i] = self.g_func(state.x[i] + state.c[i])
        # calculate new state values

        j = 7
        i = 0
        while i < 8:
            state.x[i] = (g[i] + ROTL32(g[j], 16) + ROTL32(g[j - 1], 16)) & 0xFFFFFFFF
            i += 1
            j += 1
            state.x[i] = (g[i] + ROTL32(g[j & 7], 8) + g[j - 1]) & 0xFFFFFFFF
            i += 1
            j += 1
            j &= 7

    def crypt(self, msg):
        plain = []
        msg_len = len(msg)
        c = self.ctx
        x = [0] * 4
        start = 0
        while True:
            self.next_state(c.w)
            for i in range(4):
                x[i] = c.w.x[i << 1]
            x[0] ^= (c.w.x[5] >> 16) ^ (c.w.x[3] << 16)
            x[1] ^= (c.w.x[7] >> 16) ^ (c.w.x[5] << 16)
            x[2] ^= (c.w.x[1] >> 16) ^ (c.w.x[7] << 16)
            x[3] ^= (c.w.x[3] >> 16) ^ (c.w.x[1] << 16)
            b = [0] * 16
            for i, j in enumerate(x):
                for z in range(4):
                    b[z + 4 * i] = 0xFF & (j >> (8 * z))
            for i in range(16):
                plain.append((msg[start] ^ b[i]))
                start += 1
                if start == msg_len:
                    return bytes(plain)


def st(b):
    a = ""
    for x in b:
        a += chr(x)
    return a


def p32(a):
    return pack("<I", a)


def u32(a):
    return unpack("<I", a)[0]


def u16(a):
    return unpack("<H", a)[0]


def dexor(data, key):
    return bytes([data[i] ^ key[i & 3] for i in range(0, len(data))])


def decrypt_memory(file):
    print("\033[1;31m[+] FILE: {} \033[0m".format(file))

    try:
        pe = pefile.PE(file)
    except Exception:
        return -1

    if pe.FILE_HEADER.Machine == 0x8664:
        print("[+] Sample is 64bit")
        arch_size = 8
    else:
        print("[+] Sample is 32bit")
        arch_size = 4

    if arch_size == 4:  # 32bit
        key_rule = yara.compile(
            source="rule foo: bar {strings: $a = {64 A1 30 00 00 00 53 57 89 75 F4 8B 40 0C 8B 40 1C C7 45 E8 ?? ?? ?? ?? 8B 58 08 8B 43 3C} condition: $a}"
        )
        tag_rule = yara.compile(
            source="rule foo: bar {strings: $a = {8B 45 04 B9 ?? ?? ?? ?? EB ?? 0F B7 07 8B 7D E0 8B 3C 87} condition: $a}"
        )
    else:  # 64bit
        key_rule = yara.compile(
            source="rule foo: bar {strings: $a = {25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40} condition: $a}"
        )
        tag_rule = yara.compile(
            source="rule foo: bar {strings: $a = {8B 7D ?? B8 ?? ?? ?? ?? EB 0F 41 ?? B7 018B 34 87 49 03 F0 EB ??} condition: $a}"
        )

    data = Path(file).read_bytes()

    key_offset = key_rule.match(data=data)
    tag_offset = tag_rule.match(data=data)

    if not key_offset or not tag_offset:
        print("[-] Error signature not found")
        print("-" * 100)
        return -1

    key_offset = key_offset[0].strings[0][0]
    tag_offset = tag_offset[0].strings[0][0]

    key = data[key_offset + 20 : key_offset + 20 + 4]
    tag = data[tag_offset + 4 : tag_offset + 4 + 4]

    print("[+] Xor key:", hex(u32(key)))
    print("[+] Packed code tag:", hex(u32(tag)))

    section = None
    for entry in pe.sections:
        if entry.Name.replace(b"\x00", b"") == b".rsrc":
            section = entry
            break

    if section is None:
        print("\033[92m[+] .rsrc section not found in file: {} \033[0m".format(file))
        return

    rsrc_data = section.get_data()
    encrypted_memory_offset = rsrc_data.find(tag)

    decrypted_memory = dexor(rsrc_data[encrypted_memory_offset + 4 :], key)  # DECRYPTED MEMORY

    key_pattern_rule32 = """
        rule key_pattern_rule
        {
            strings:
                $pattern1 = {FC 22 F3 66 0F B3 C1 8B 4D 08 81 F1 ?? ?? ?? ?? 8B 55 FC 39 0A}
                $pattern2 = {8B 4D 08 ?? ?? ?? ?? ?? ?? ?? 81 F1 ?? ?? ?? ?? 8B 55 FC ?? ?? ?? 39 0A 0F}
            condition: any of them
        }
    """
    key_pattern_rule32 = yara.compile(source=key_pattern_rule32)
    key_pattern_offset32 = key_pattern_rule32.match(data=decrypted_memory)

    key_pattern_rule64 = yara.compile(
        source="rule foo: bar {strings: $a = {?? 41 0F 4A CE 80 C1 ?? 41 0A CA 35 ?? ?? ?? ?? 86 E9 48 8B 4C 24 ?? F6 C1 ??} condition: $a}"
    )
    key_pattern_offset64 = key_pattern_rule64.match(data=decrypted_memory)

    if key_pattern_offset32:  # 32bit samples
        key_pattern_offset = key_pattern_offset32[0].strings[0][0]
        key_pattern = decrypted_memory[key_pattern_offset + 12 : key_pattern_offset + 12 + 4]
    elif key_pattern_offset64:  # 64bit samples
        key_pattern_offset = key_pattern_offset64[0].strings[0][0]
        key_pattern = decrypted_memory[key_pattern_offset + 12 : key_pattern_offset + 12 + 4]
    else:
        print("[-] key_pattern_rule Error signature not found")
        print("-" * 100)
        return 0

    config_tag = (u32(key)) ^ (u32(key_pattern))

    print("[+] Config tag:", hex(config_tag))

    encrypted_config_offset = rsrc_data.rfind(p32(config_tag))

    if encrypted_config_offset == -1:
        print("Encrypted config not found")
        return -1

    config_size = 0x644

    decrypted_config = dexor(
        rsrc_data[encrypted_config_offset + 4 : encrypted_config_offset + 4 + config_size],
        key,
    )

    key = decrypted_config[0x62C : 0x62C + 16]
    iv = decrypted_config[0x63C : 0x63C + 8]
    compressed_data_size = decrypted_config[0x624 : 0x624 + 4]
    uncompressed_data_size = decrypted_config[0x628 : 0x628 + 4]
    flag = u16(decrypted_config[0:2])
    payload_export_hash = decrypted_config[2:6]
    MZ = True
    w_payload_filename_and_cmdline = ""
    sleep_after_injection = True if (flag & 0x100) != 0 else False
    persistance = True if (flag & 1) != 0 else False
    if persistance:
        w_payload_filename_and_cmdline = decrypted_config[6:0x210].split(b"\x00\x00")[0].replace(b"\x00", b"").decode()
    if (flag & 2) != 0:
        injection_method = "Reflective injection"
    elif (flag & 0x40) != 0:
        injection_method = "Execute shellcode"
        MZ = False
    else:
        if (flag & 8) != 0:
            injection_method = "Process hollowing current executable (rundll32.exe in case of a DLL sample)"
        elif (flag & 0x10) != 0:
            injection_method = "Process hollowing IE or Werfault"

    config = {
        "Flag": hex(flag),
        "Payload_export_hash": hex(u32(payload_export_hash)),
        "w_payload_filename": w_payload_filename_and_cmdline,
        "Compressed_data_size": hex(u32(compressed_data_size)),
        "Uncompressed_data_size": hex(u32(uncompressed_data_size)),
        "Rabbit key": binascii.hexlify(key).decode(),
        "Rabbit iv": binascii.hexlify(iv).decode(),
        "Persistance": persistance,
        "Sleep after injection": sleep_after_injection,
        "Injection method": injection_method,
    }

    print("[+] Blister configuration:")
    print(json.dumps(config, indent=4))

    # decrypt payload

    encrypted_payload = rsrc_data[
        encrypted_config_offset + 4 + config_size : encrypted_config_offset + 4 + config_size + u32(compressed_data_size)
    ]  # 4 == tag size

    cipher = Rabbit(bytes(key), bytes(iv))

    decrypted_payload = cipher.crypt(bytes(encrypted_payload))

    uncompressed_payload = lznt1(decrypted_payload)

    save_payload_path = "{}_payload".format(file)

    print("\033[92m[+] Payload extracted and saved to: {} \033[0m".format(save_payload_path))

    if MZ:
        uncompressed_payload = b"MZ" + uncompressed_payload[2:]

    _ = Path(save_payload_path).write_bytes(uncompressed_payload)


def main():
    print("Author: @Soolidsnake")
    print(
        """
  ____   _  _       _                                    __  _                      _                      _
 |  _ \ | |(_)     | |                                  / _|(_)                    | |                    | |
 | |_) || | _  ___ | |_  ___  _ __    ___  ___   _ __  | |_  _   __ _    ___ __  __| |_  _ __  __ _   ___ | |_  ___   _ __
 |  _ < | || |/ __|| __|/ _ \| '__|  / __|/ _ \ | '_ \ |  _|| | / _` |  / _ \\\\ \/ /| __|| '__|/ _` | / __|| __|/ _ \ | '__|
 | |_) || || |\__ \| |_|  __/| |    | (__| (_) || | | || |  | || (_| | |  __/ >  < | |_ | |  | (_| || (__ | |_| (_) || |
 |____/ |_||_||___/ \__|\___||_|     \___|\___/ |_| |_||_|  |_| \__, |  \___|/_/\_\ \__||_|   \__,_| \___| \__|\___/ |_|
                                                                 __/ |
                                                                |___/
"""  # noqa: W605
    )
    parser = OptionParser()

    parser.add_option("-f", "--file", dest="filename", help="file", metavar="file")
    parser.add_option("-d", "--dir", dest="dirname", help="directory", metavar="dir")
    (options, args) = parser.parse_args()
    file_path = options.filename
    dir_path = options.dirname
    if file_path is None and dir_path is None:
        parser.print_help()
        sys.exit(1)

    if file_path and os.path.isfile(file_path):
        decrypt_memory(file_path)

    if dir_path and os.path.isdir(dir_path):
        for (dirpath, _, filenames) in os.walk(dir_path):
            for file in filenames:
                decrypt_memory(os.path.join(dirpath, file))


if __name__ == "__main__":
    main()

# CAPE: Derived from decrypt_memory()
def extract_config(data):
    try:
        pe = pefile.PE(data=data)
    except Exception:
        log.info("Not a PE file")
        return -1

    if pe.FILE_HEADER.Machine == 0x8664:
        arch_size = 8
    else:
        arch_size = 4

    if arch_size == 4:  # 32bit
        key_rule = yara.compile(
            source="rule foo: bar {strings: $a = {64 A1 30 00 00 00 53 57 89 75 F4 8B 40 0C 8B 40 1C C7 45 E8 ?? ?? ?? ?? 8B 58 08 8B 43 3C} condition: $a}"
        )
        tag_rule = yara.compile(
            source="rule foo: bar {strings: $a = {8B 45 04 B9 ?? ?? ?? ?? EB ?? 0F B7 07 8B 7D E0 8B 3C 87} condition: $a}"
        )
    else:  # 64bit
        key_rule = yara.compile(
            source="rule foo: bar {strings: $a = {25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40} condition: $a}"
        )
        tag_rule = yara.compile(
            source="rule foo: bar {strings: $a = {8B 7D ?? B8 ?? ?? ?? ?? EB 0F 41 ?? B7 018B 34 87 49 03 F0 EB ??} condition: $a}"
        )

    key_offset = key_rule.match(data=data)
    tag_offset = tag_rule.match(data=data)

    if not key_offset or not tag_offset:
        log.info("Error: signature not found")
        return -1

    key_offset = key_offset[0].strings[0][0]
    tag_offset = tag_offset[0].strings[0][0]

    key = data[key_offset + 20 : key_offset + 20 + 4]
    tag = data[tag_offset + 4 : tag_offset + 4 + 4]

    section = None
    for entry in pe.sections:
        if entry.Name.replace(b"\x00", b"") == b".rsrc":
            section = entry
            break

    if section is None:
        log.info("rsrc section not found")
        return

    rsrc_data = section.get_data()
    encrypted_memory_offset = rsrc_data.find(tag)

    decrypted_memory = dexor(rsrc_data[encrypted_memory_offset + 4 :], key)  # DECRYPTED MEMORY

    key_pattern_rule32 = """
        rule key_pattern_rule
        {
            strings:
                $pattern1 = {FC 22 F3 66 0F B3 C1 8B 4D 08 81 F1 ?? ?? ?? ?? 8B 55 FC 39 0A}
                $pattern2 = {8B 4D 08 ?? ?? ?? ?? ?? ?? ?? 81 F1 ?? ?? ?? ?? 8B 55 FC ?? ?? ?? 39 0A 0F}
            condition: any of them
        }
    """
    key_pattern_rule32 = yara.compile(source=key_pattern_rule32)
    key_pattern_offset32 = key_pattern_rule32.match(data=decrypted_memory)

    key_pattern_rule64 = yara.compile(
        source="rule foo: bar {strings: $a = {?? 41 0F 4A CE 80 C1 ?? 41 0A CA 35 ?? ?? ?? ?? 86 E9 48 8B 4C 24 ?? F6 C1 ??} condition: $a}"
    )
    key_pattern_offset64 = key_pattern_rule64.match(data=decrypted_memory)

    if key_pattern_offset32:  # 32bit samples
        key_pattern_offset = key_pattern_offset32[0].strings[0][0]
        key_pattern = decrypted_memory[key_pattern_offset + 12 : key_pattern_offset + 12 + 4]
    elif key_pattern_offset64:  # 64bit samples
        key_pattern_offset = key_pattern_offset64[0].strings[0][0]
        key_pattern = decrypted_memory[key_pattern_offset + 12 : key_pattern_offset + 12 + 4]
    else:
        log.info("key_pattern_rule: Error signature not found")
        return 0

    config_tag = (u32(key)) ^ (u32(key_pattern))

    encrypted_config_offset = rsrc_data.rfind(p32(config_tag))

    if encrypted_config_offset == -1:
        log.info("Encrypted config not found")
        return -1

    config_size = 0x644

    decrypted_config = dexor(
        rsrc_data[encrypted_config_offset + 4 : encrypted_config_offset + 4 + config_size],
        key,
    )

    key = decrypted_config[0x62C : 0x62C + 16]
    iv = decrypted_config[0x63C : 0x63C + 8]
    compressed_data_size = decrypted_config[0x624 : 0x624 + 4]
    uncompressed_data_size = decrypted_config[0x628 : 0x628 + 4]
    flag = u16(decrypted_config[0:2])
    payload_export_hash = decrypted_config[2:6]
    w_payload_filename_and_cmdline = ""
    sleep_after_injection = True if (flag & 0x100) != 0 else False
    persistance = True if (flag & 1) != 0 else False
    if persistance:
        w_payload_filename_and_cmdline = decrypted_config[6:0x210].split(b"\x00\x00")[0].replace(b"\x00", b"").decode()
    if (flag & 2) != 0:
        injection_method = "Reflective injection"
    elif (flag & 0x40) != 0:
        injection_method = "Execute shellcode"
    else:
        if (flag & 8) != 0:
            injection_method = "Process hollowing current executable (rundll32.exe in case of a DLL sample)"
        elif (flag & 0x10) != 0:
            injection_method = "Process hollowing IE or Werfault"

    config = {
        "Flag": hex(flag),
        "Payload export hash": hex(u32(payload_export_hash)),
        "Payload filename": w_payload_filename_and_cmdline,
        "Compressed data size": hex(u32(compressed_data_size)),
        "Uncompressed data size": hex(u32(uncompressed_data_size)),
        "Rabbit key": binascii.hexlify(key).decode(),
        "Rabbit IV": binascii.hexlify(iv).decode(),
        "Persistence": persistance,
        "Sleep after injection": sleep_after_injection,
        "Injection method": injection_method,
    }

    return config
