#!/usr/bin/env python3
#
# config_item.py
#
# Author: jeFF0Falltrades
#
# Provides a utility class for parsing RAT config values of various types
# from a config using the known format of AsyncRAT, DcRAT, QuasarRAT, VenomRAT,
# etc.
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
from .data_utils import bytes_to_int
from .dotnet_constants import OPCODE_LDC_I4_0, SpecialFolder
from logging import getLogger
from re import findall, DOTALL

logger = getLogger(__name__)


# Provides an abstract class for config items
class ConfigItem:
    def __init__(self, label, pattern):
        self.label = label
        self.pattern = pattern

    # Should be overridden by children to provide a meaningful value
    def derive_item_value(self):
        return None

    # Derives config field RVAs and values from data using the specified
    # ConfigItem's pattern
    def parse_from(self, data):
        logger.debug(f"Parsing {self.label} values from data...")
        fields = {}
        raw_data = findall(self.pattern, data, DOTALL)
        found_items = 0
        for obj, string_rva in raw_data:
            try:
                field_value = self.derive_item_value(obj)
                field_rva = bytes_to_int(string_rva)
            except Exception:
                logger.debug(f"Could not parse value from {obj} at {string_rva}")
                continue
            fields[field_rva] = field_value
            found_items += 1
        logger.debug(f"Parsed {found_items} {self.label} values")
        return fields


class BoolConfigItem(ConfigItem):
    def __init__(self):
        super().__init__("boolean", b"(\x16|\x17)\x80(.{4})")

    # Boolean values are derived by examing if the opcode is "ldc.i4.0" (False)
    # or "ldc.i4.1" (True)
    def derive_item_value(self, opcode):
        return bool(bytes_to_int(opcode) - bytes_to_int(OPCODE_LDC_I4_0))


class IntConfigItem(ConfigItem):
    def __init__(self):
        super().__init__("int", b"\x20(.{4})\x80(.{4})")

    # Simply look for which int was loaded by "ldc.i4"
    def derive_item_value(self, int_bytes):
        return bytes_to_int(int_bytes)


class NullConfigItem(ConfigItem):
    def __init__(self):
        super().__init__("null", b"\x14\x80{.4}")

    # If "ldnull" is being used, simply return "null"
    def derive_item_value(self, _):
        return "null"


class SpecialFolderConfigItem(ConfigItem):
    def __init__(self):
        super().__init__("special folder", b"\x1f(.)\x80(.{4})")

    # Translates SpecialFolder ID to name
    def derive_item_value(self, folder_id):
        return SpecialFolder(bytes_to_int(folder_id)).name


class EncryptedStringConfigItem(ConfigItem):
    def __init__(self):
        super().__init__("encrypted string", b"\x72(.{4})\x80(.{4})")

    # Returns the encrypted string's RVA
    def derive_item_value(self, enc_str_rva):
        return bytes_to_int(enc_str_rva)
