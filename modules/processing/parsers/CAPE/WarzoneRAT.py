# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct
from contextlib import suppress

import pefile

DESCRIPTION = "WarzoneRAT configuration extractor."
AUTHOR = "enzo"


def ksa(key: bytearray) -> bytearray:
    sbox = bytearray(256)
    for i in range(256):
        sbox[i] = i

    j = 0
    for i in range(256):
        j = (j + key[i % 250] + sbox[i]) & 0xFF
        sbox[i] ^= sbox[j] & 0xFF
        sbox[j] ^= sbox[i] & 0xFF
        sbox[i] ^= sbox[j] & 0xFF
    return sbox


def decrypt(sbox: bytearray, src_buf: bytearray) -> bytes:
    i, j, k = 0, 0, 0
    dst_buf = bytearray(len(src_buf))

    while k < len(src_buf):
        i += 1
        uc = sbox[i % 256] & 0xFF
        c = uc - 256 if uc > 127 else uc
        j = j + c - 256 if j + c > 256 else j + c
        d = sbox[j % 256]
        sbox[i % 256] = d
        sbox[j % 256] = uc
        e1 = (i >> 3) ^ (32 * j)
        e = sbox[e1 % 256]
        g1 = ((int.from_bytes(struct.pack(">i", j), "big") >> 3) ^ (32 * i)) & 0xFF
        g2 = sbox[g1 % 256]
        g = (e + g2) & 0xFF
        e = sbox[(j + d) % 256]
        h = sbox[(g ^ 0xAA) % 256]
        xor_key = (e ^ (h + sbox[(d + uc) % 256])) & 0xFF
        dst_buf[k] = src_buf[k] ^ xor_key
        i += 1
        k += 1

    return bytes(dst_buf)


def extract_bss_data(pe):
    for section in pe.sections:
        if b".bss" in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None


def extract_config(data):
    cfg = {}
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=data, fast_load=False)
    if not pe:
        return
    try:
        key = bytearray(250)
        bss_data = extract_bss_data(pe)
        if not bss_data:
            return cfg
        key_size = struct.unpack("i", bss_data[:4])[0]
        key_bytes = bss_data[4 : 4 + key_size]
        for k in range(len(key_bytes)):
            key[k] = key_bytes[k]
        etxt = bss_data[4 + key_size : 260 + key_size]
        dtxt = decrypt(ksa(key), bytearray(etxt))

        offset = 4
        c2_size = struct.unpack("i", dtxt[:offset])[0]
        c2_host = dtxt[offset : offset + c2_size].decode("utf-16")
        offset += c2_size
        c2_port = struct.unpack("H", dtxt[offset : offset + 2])[0]
        cfg["C2"] = f"{c2_host}:{c2_port}"
        offset += 2
        # unk1 = dtxt[offset : offset + 7]
        offset += 7
        unk2_size = struct.unpack("i", dtxt[offset : offset + 4])[0]
        offset += 4
        # unk2 = dtxt[offset : offset + unk2_size]
        offset += unk2_size
        # unk3 = dtxt[offset : offset + 2]
        offset += 2
        runkey_size = struct.unpack("i", dtxt[offset : offset + 4])[0]
        offset += 4
        cfg["Run Key Name"] = dtxt[offset : offset + runkey_size].decode("utf-16")
    except struct.error:
        # there is a lot of failed data validation muting it
        return
    except Exception as e:
        print("warzone", e)

    return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
