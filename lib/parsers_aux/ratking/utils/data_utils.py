#!/usr/bin/env python3
#
# data_utils.py
#
# Author: jeFF0Falltrades
#
# Provides various utility functions for working with binary data
#
# MIT License
#
# Copyright (c) 2024 Jeff Archer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from .config_parser_exception import ConfigParserException


# Converts a bytes object to an int object using the specified byte order
def bytes_to_int(bytes, order="little"):
    try:
        return int.from_bytes(bytes, byteorder=order)
    except Exception as e:
        raise ConfigParserException(f"Error parsing int from value: {bytes}") from e


# Decodes a bytes object to a Unicode string, using UTF-16LE for byte values
# with null bytes still embedded in them, and UTF-8 for all other values
def decode_bytes(byte_str):
    if isinstance(byte_str, str):
        return byte_str.strip()
    result = None
    try:
        if b"\x00" in byte_str:
            result = byte_str.decode("utf-16le")
        else:
            result = byte_str.decode("utf-8")
    except Exception as e:
        raise ConfigParserException(
            f"Error decoding bytes object to Unicode: {byte_str}"
        ) from e
    return result


def int_to_bytes(int, length=4, order="little"):
    try:
        return int.to_bytes(length, order)
    except Exception as e:
        raise ConfigParserException(f"Error parsing bytes from value: {int}") from e
