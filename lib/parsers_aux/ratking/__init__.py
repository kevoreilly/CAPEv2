#!/usr/bin/env python3
#
# rat_config_parser.py
#
# Author: jeFF0Falltrades
#
# Provides the primary functionality for parsing configurations from the
# AsyncRAT, DcRAT, QuasarRAT, VenomRAT, etc. RAT families
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
from logging import getLogger
from re import DOTALL, search

from .utils import config_item
from .utils.config_parser_exception import ConfigParserException
from .utils.decryptors import SUPPORTED_DECRYPTORS
from .utils.dotnet_constants import OPCODE_RET
from .utils.dotnetpe_payload import DotNetPEPayload

logger = getLogger(__name__)


class RATConfigParser:
    CONFIG_ITEM_TYPES = [
        config_item.BoolConfigItem(),
        config_item.ByteArrayConfigItem(),
        config_item.IntConfigItem(),
        config_item.NullConfigItem(),
        config_item.SpecialFolderConfigItem(),
        config_item.EncryptedStringConfigItem(),
    ]
    MIN_CONFIG_LEN = 7
    PATTERN_VERIFY_HASH = rb"(?:\x7e.{3}\x04(?:\x6f.{3}\x0a){2}\x74.{3}\x01.+?\x2a.+?\x00{6,})"

    def __init__(self, file_data=False):
        self.report = {"config": {}}
        try:

            self.dnpp = DotNetPEPayload(file_data)
            # self.report["sha256"] = self.dnpp.sha256
            # self.report["possible_yara_family"] = self.dnpp.yara_match
            if self.dnpp.dotnetpe is None:
                raise ConfigParserException("Failed to load file as .NET executable")
            self.decryptor = None  # Created in decrypt_and_decode_config()
            self.report["config"] = self.get_config()
            self.report["config"]["aes_key"] = (
                self.decryptor.key.hex() if self.decryptor is not None and self.decryptor.key is not None else "None"
            )
            self.report["config"]["aes_salt"] = (
                self.decryptor.salt.hex() if self.decryptor is not None and self.decryptor.salt is not None else "None"
            )
        except Exception as e:
            self.report["config"] = f"Exception encountered: {e}"

    # Decrypts/decodes values from an encrypted config
    def decrypt_and_decode_config(self, encrypted_config):
        decoded_config = {}
        selected_decryptor = 0
        for item in self.CONFIG_ITEM_TYPES:
            item_data = item.parse_from(encrypted_config)
            if len(item_data) > 0:
                if type(item) is config_item.EncryptedStringConfigItem:
                    # Translate encrypted string RVAs to encrypted values
                    for k in item_data:
                        item_data[k] = self.dnpp.user_string_from_rva(item_data[k])
                    # Decrypt the values
                    while selected_decryptor < len(SUPPORTED_DECRYPTORS):
                        try:
                            if self.decryptor is None:
                                self.decryptor = SUPPORTED_DECRYPTORS[selected_decryptor](self.dnpp, item_data)
                            item_data = self.decryptor.decrypt_encrypted_strings()
                            break
                        except Exception as e:
                            logger.debug(
                                f"Decryption failed with decryptor {SUPPORTED_DECRYPTORS[selected_decryptor]} : {e}, trying next decryptor..."
                            )
                            self.decryptor = None
                            selected_decryptor += 1
                elif type(item) is config_item.ByteArrayConfigItem:
                    for k in item_data:
                        arr_size, arr_rva = item_data[k]
                        item_data[k] = self.dnpp.byte_array_from_size_and_rva(arr_size, arr_rva).hex()
                decoded_config.update(item_data)
        if len(decoded_config) < self.MIN_CONFIG_LEN:
            raise ConfigParserException("Minimum threshold of config items not met")
        return decoded_config

    # Searches for the RAT configuration in the Settings module
    def get_config(self):
        logger.debug("Extracting config...")
        try:
            config_start, decrypted_config = self.get_config_verify_hash_method()
        except Exception:
            logger.debug("VerifyHash() method failed; Attempting .cctor brute force...")
            # If the typical patterns are not found, start brute-forcing
            try:
                config_start, decrypted_config = self.get_config_cctor_brute_force()
            except Exception as e:
                raise ConfigParserException("Could not identify config") from e
        logger.debug(f"Config found at offset {hex(config_start)}...")
        return self.translate_config_field_names(decrypted_config)

    # Attempts to retrieve the config via brute-force, looking through every
    # static constructor (.cctor) and attempting to decode/decrypt a valid
    # config from that constructor
    def get_config_cctor_brute_force(self):
        candidates = self.dnpp.method_rvas_from_name(".cctor")
        if len(candidates) == 0:
            raise ConfigParserException("No .cctor method could be found")
        # Get each .cctor method RVA and bytes content up to a RET op
        candidate_data = {rva: self.dnpp.string_from_offset(self.dnpp.offset_from_rva(rva), OPCODE_RET) for rva in candidates}
        config_start, decrypted_config = None, None
        for method_rva, method_ins in candidate_data.items():
            logger.debug(f"Attempting brute force at .cctor method at {hex(method_rva)}")
            try:
                config_start, decrypted_config = (
                    method_rva,
                    self.decrypt_and_decode_config(method_ins),
                )
                break
            except Exception as e:
                logger.debug(e)
                continue
        if decrypted_config is None:
            raise ConfigParserException("No valid configuration could be parsed from any .cctor methods")
        return config_start, decrypted_config

    # Attempts to retrieve the config via looking for a config section preceded
    # by the "VerifyHash()" function that is typically found in the Settings
    # module
    def get_config_verify_hash_method(self):
        # Identify the VerifyHash() Method code
        hit = search(self.PATTERN_VERIFY_HASH, self.dnpp.data, DOTALL)
        if hit is None:
            raise ConfigParserException("Could not identify VerifyHash() marker method")
        # Reverse the VerifyHash() instruction offset, look up VerifyHash() in
        # the MethodDef metadata table, and then get the offset to the
        # subsequent function, which should be our config constructor
        config_start = self.dnpp.next_method_from_instruction_offset(hit.start())
        # Configuration ends with ret operation, so use that as our terminator
        encrypted_config = self.dnpp.string_from_offset(config_start, OPCODE_RET)
        decrypted_config = self.decrypt_and_decode_config(encrypted_config)
        return config_start, decrypted_config

    # Sorts the config by field name RVA prior to replacing RVAs with field
    # name strings (this is done last to preserve config ordering)
    def translate_config_field_names(self, decrypted_config):
        translated_config = {}
        for field_rva, field_value in sorted(decrypted_config.items()):
            key = self.dnpp.field_name_from_rva(field_rva)
            translated_config[key] = field_value
            logger.debug(f"Config item parsed {key}: {field_value}")
        return translated_config
