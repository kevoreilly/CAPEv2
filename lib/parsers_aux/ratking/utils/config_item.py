#!/usr/bin/env python3
#
# config_item.py
#
# Author: jeFF0Falltrades
#
# Provides a utility class for parsing field names and values of various types
# from raw RAT config data
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
from abc import ABC, abstractmethod
from logging import getLogger
from re import DOTALL, compile, findall
from typing import Any, Tuple

from .data_utils import bytes_to_int
from .dotnet_constants import OPCODE_LDC_I4_0, SpecialFolder

logger = getLogger(__name__)


# Provides an abstract class for config items
class ConfigItem(ABC):
    def __init__(self, label: str, pattern: bytes) -> None:
        self._label = label
        self._pattern = compile(pattern, flags=DOTALL)

    # Should be overridden by children to provide a meaningful value
    @abstractmethod
    def _derive_item_value(self) -> Any:
        pass

    # Derives config Field RVAs and values from data using the specified
    # ConfigItem's pattern
    def parse_from(self, data: bytes) -> dict[int, Any]:
        logger.debug(f"Parsing {self._label} values from data...")
        fields = {}
        raw_data = findall(self._pattern, data)
        found_items = 0
        for obj, bytes_rva in raw_data:
            try:
                field_value = self._derive_item_value(obj)
                field_rva = bytes_to_int(bytes_rva)
            except Exception:
                logger.debug(f"Could not parse value from {obj} at {hex(bytes_rva)}")
                continue
            if field_rva not in fields:
                fields[field_rva] = field_value
                found_items += 1
            else:
                logger.debug(
                    f"Overlapping Field RVAs detected in config at {hex(field_rva)}"
                )
        logger.debug(f"Parsed {found_items} {self._label} values")
        return fields


class BoolConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("boolean", b"(\x16|\x17)\x80(.{3}\x04)")

    # Boolean values are derived by examing if the opcode is "ldc.i4.0" (False)
    # or "ldc.i4.1" (True)
    def _derive_item_value(self, opcode: bytes) -> bool:
        return bool(bytes_to_int(opcode) - bytes_to_int(OPCODE_LDC_I4_0))


class ByteArrayConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__(
            "byte array",
            rb"\x1f(.\x8d.{3}\x01\x25\xd0.{3}\x04)\x28.{3}\x0a\x80(.{3}\x04)",
        )

    # Byte array size and RVA are returned, as these are needed to
    # extract the value of the bytes from the payload
    def _derive_item_value(self, byte_data: bytes) -> Tuple[int, int]:
        arr_size = byte_data[0]
        arr_rva = bytes_to_int(byte_data[-4:])
        return (arr_size, arr_rva)


class IntConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("int", b"(\x20.{4}|[\x18-\x1e])\x80(.{3}\x04)")

    def _derive_item_value(self, int_bytes: bytes) -> int:
        # If single byte, must be value 2-8, represented by opcodes 0x18-0x1e
        # Subtract 0x16 to get the int value, e.g.:
        # ldc.i4.8 == 0x1e - 0x16 == 8
        if len(int_bytes) == 1:
            return bytes_to_int(int_bytes) - 0x16
        # Else, look for which int was loaded by "ldc.i4"
        return bytes_to_int(int_bytes[1:])


class NullConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("null", b"(\x14\x80)(.{3}\x04)")

    # If "ldnull" is being used, simply return "null"
    def _derive_item_value(self, _: bytes) -> str:
        return "null"


class SpecialFolderConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("special folder", b"\x1f(.)\x80(.{3}\x04)")

    # Translates SpecialFolder ID to name
    def _derive_item_value(self, folder_id: bytes) -> str:
        return SpecialFolder(bytes_to_int(folder_id)).name


class EncryptedStringConfigItem(ConfigItem):
    def __init__(self) -> None:
        super().__init__("encrypted string", b"\x72(.{3}\x70)\x80(.{3}\x04)")

    # Returns the encrypted string's RVA
    def _derive_item_value(self, enc_str_rva: bytes) -> int:
        return bytes_to_int(enc_str_rva)


SUPPORTED_CONFIG_ITEMS = [
    BoolConfigItem,
    ByteArrayConfigItem,
    IntConfigItem,
    NullConfigItem,
    SpecialFolderConfigItem,
    EncryptedStringConfigItem,
]
