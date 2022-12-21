# included from https://github.com/sysopfb/brieflz

import binascii
import os
import struct
import zlib
from ctypes import byref, c_int, cdll, create_string_buffer

CURR_DIR = os.path.abspath(os.path.dirname(__file__))
LIB_PATH = os.path.join(CURR_DIR, "blzpack_lib.so")
brieflz = cdll.LoadLibrary(LIB_PATH)


DEFAULT_BLOCK_SIZE = 1024 * 1024


def compress_data(data, blocksize, level):
    compressed_data = ""
    while len(data) > 0:
        buf = create_string_buffer(data[:blocksize])
        cb = c_int(len(buf))
        cbOut = brieflz.blz_max_packed_size(blocksize)
        packed = create_string_buffer(cbOut)
        workmem = create_string_buffer(brieflz.blz_workmem_size_level(blocksize, 1))
        cbOut = c_int(cbOut)
        retval = brieflz.blz_pack_level(byref(buf), byref(packed), cb, byref(workmem), level)
        if retval > 0:
            temp = packed.raw[:retval]
            tempret = (
                struct.pack(
                    ">IIIIII",
                    1651276314,
                    level,
                    len(temp),
                    zlib.crc32(temp) % (1 << 32),
                    len(buf),
                    zlib.crc32(data[:blocksize]) % (1 << 32),
                )
                + temp
            )
            compressed_data += tempret
        else:
            print("Compression Error")
            return None
        data = data[blocksize:]
    return compressed_data


def decompress_data(data, blocksize=DEFAULT_BLOCK_SIZE, level=1):
    decompressed_data = b""
    # max_packed_size = brieflz.blz_max_packed_size(blocksize)

    (magic, level, packedsize, crc, hdr_depackedsize, crc2) = struct.unpack_from(">IIIIII", data)
    data = data[24:]
    while magic == 0x626C7A1A and len(data) > 0:
        compressed_data = create_string_buffer(data[:packedsize])
        workdata = create_string_buffer(blocksize)
        depackedsize = brieflz.blz_depack(byref(compressed_data), byref(workdata), c_int(hdr_depackedsize))
        if depackedsize != hdr_depackedsize:
            print("Decompression error")
            print(f"DepackedSize: {depackedsize}\nHdrVal: {hdr_depackedsize}")
            return None
        decompressed_data += workdata.raw[:depackedsize]
        data = data[packedsize:]
        if len(data) > 0:
            (magic, level, packedsize, crc, hdr_depackedsize, crc2) = struct.unpack_from(">IIIIII", data)
            data = data[24:]
        else:
            break
    return decompressed_data


def main():
    # blocksize = DEFAULT_BLOCK_SIZE
    blocksize = 100
    level = 1
    data = "This is a test of brieflz compression" * 100
    retval = compress_data(data, blocksize, level)
    if retval is not None:
        print("Compression SUCCESS!\nCompressed Data: ")
        print(binascii.hexlify(retval))
        retval = decompress_data(retval, blocksize, level)
        if retval is not None and retval == data:
            print("Decompress SUCCESS!\nDecompress Data: ")
            print(retval)


if __name__ == "__main__":
    main()
