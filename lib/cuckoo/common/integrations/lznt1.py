# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""Decompression support for the LZNT1 compression algorithm.

Reference:
http://msdn.microsoft.com/en-us/library/jj665697.aspx
(2.5 LZNT1 Algorithm Details)

https://github.com/libyal/reviveit/
https://github.com/sleuthkit/sleuthkit/blob/develop/tsk/fs/ntfs.c
"""
import array
import struct
from io import BytesIO

__all__ = ["Lznt1", "lznt1"]


def get_displacement(offset: int) -> int:
    """Calculate the displacement."""
    result = 0
    while offset >= 0x10:
        offset >>= 1
        result += 1

    return result


DISPLACEMENT_TABLE = array.array("B", [get_displacement(x) for x in range(8192)])

COMPRESSED_MASK = 1 << 15
SIGNATURE_MASK = 3 << 12
SIZE_MASK = (1 << 12) - 1
TAG_MASKS = [(1 << i) for i in range(0, 8)]


def decompress_data(cdata: bytes) -> bytes:
    """Decompresses the data."""
    block_end = 0

    with BytesIO(cdata) as in_fd, BytesIO() as output_fd:
        while in_fd.tell() < len(cdata):
            block_offset = in_fd.tell()
            uncompressed_chunk_offset = output_fd.tell()

            block_header = struct.unpack("<H", in_fd.read(2))[0]

            if block_header & SIGNATURE_MASK != SIGNATURE_MASK:
                break

            size = block_header & SIZE_MASK

            block_end = block_offset + size + 3

            if block_header & COMPRESSED_MASK:
                while in_fd.tell() < block_end:
                    header = ord(in_fd.read(1))

                    for mask in TAG_MASKS:
                        if in_fd.tell() >= block_end:
                            break

                        if header & mask:
                            pointer = struct.unpack("<H", in_fd.read(2))[0]
                            displacement = DISPLACEMENT_TABLE[output_fd.tell() - uncompressed_chunk_offset - 1]

                            symbol_offset = (pointer >> (12 - displacement)) + 1
                            symbol_length = (pointer & (0xFFF >> displacement)) + 3

                            output_fd.seek(-symbol_offset, 2)
                            data = output_fd.read(symbol_length)

                            # Pad the data to make it fit.
                            if 0 < len(data) < symbol_length:
                                data = data * (symbol_length // len(data) + 1)
                                data = data[:symbol_length]

                            output_fd.seek(0, 2)

                            output_fd.write(data)

                        else:
                            data = in_fd.read(1)

                            output_fd.write(data)

            else:
                # Block is not compressed
                data = in_fd.read(size + 1)
                output_fd.write(data)

        result = output_fd.getvalue()

        return result


class Lznt1:
    """
    Implementation of LZNT1 decompression. Allows to decompress data compressed by RtlCompressBuffer
    .. code-block:: python
        from malduck import lznt1
        lznt1(b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot")
    :param buf: Buffer to decompress
    :type buf: bytes
    :rtype: bytes
    """

    def decompress(self, buf: bytes) -> bytes:
        return decompress_data(buf)

    __call__ = decompress


lznt1 = Lznt1()
