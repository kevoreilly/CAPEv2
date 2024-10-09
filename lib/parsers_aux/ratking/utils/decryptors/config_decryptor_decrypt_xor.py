#!/usr/bin/env python3
#
# config_decryptor_decrypt_xor.py
#
# Author: jeFF0Falltrades
#
# Provides a custom decryptor for RAT payloads utilizing the DecryptXOR
# method of embeddeding config strings
#
# Example Hash: 6e5671dec52db7f64557ba8ef70caf53cf0c782795236b03655623640f9e6a83
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
from re import DOTALL, compile, findall, search

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes
from ..dotnet_constants import PATTERN_LDSTR_OP
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import ConfigDecryptor, IncompatibleDecryptorException
from .config_decryptor_plaintext import ConfigDecryptorPlaintext

logger = getLogger(__name__)


class ConfigDecryptorDecryptXOR(ConfigDecryptor):
    _KEY_XOR_DECODED_STRINGS = "xor_decoded_strings"

    # Pattern to detect usage of DecryptXOR Method
    _PATTERN_DECRYPT_XOR_BLOCK = compile(
        rb"(\x2d.\x72.{3}\x70\x28.{3}\x06\x2a(?:\x02[\x16-\x1f].?\x33.\x72.{3}\x70\x28.{3}\x06\x2a){7,}.+?\x72.{3}\x70)",
        flags=DOTALL,
    )

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        # Filled in _get_xor_metadata()
        self._xor_strings: list[str] = []
        try:
            self._get_xor_metadata()
        except Exception as e:
            raise IncompatibleDecryptorException(e)

    # Returns a list of decoded XOR-encoded strings found in the payload
    def _decode_encoded_strings(self) -> list[str]:
        decoded_strings = []

        for string in self._xor_strings:
            decoded = []
            # Do not modify unencoded strings
            if ":" not in string:
                decoded_strings.append(string)
                continue

            # Split encoded string by ':' and run XOR decoding
            arr, arr2 = (bytes.fromhex(arr) for arr in string.split(":"))
            for idx, byte in enumerate(arr2):
                decoded.append(byte ^ self.key[idx % len(self.key)] ^ arr[idx])
            decoded_strings.append(decode_bytes(bytes(decoded)))

        logger.debug(f"Decoded {len(decoded_strings)} strings")
        return decoded_strings

    # Parses the config, adds decoded XOR strings, and returns the decoded
    # config
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, list[str] | str]:
        config = {}
        # Pass off plaintext config to a ConfigDecryptorPlaintext
        ptcd = ConfigDecryptorPlaintext(self._payload)
        config.update(ptcd.decrypt_encrypted_strings(encrypted_strings))
        config[self._KEY_XOR_DECODED_STRINGS] = self._decode_encoded_strings()
        return config

    # Gathers XOR metadata from the payload
    def _get_xor_metadata(self):
        dxor_block = search(self._PATTERN_DECRYPT_XOR_BLOCK, self._payload.data)
        if dxor_block is None:
            raise ConfigParserException("Could not identify DecryptXOR block")
        logger.debug(f"DecryptXOR block found at offset {hex(dxor_block.start())}")

        # Derive all XOR-encoded string references in the DecryptXOR block
        xor_string_rvas = findall(PATTERN_LDSTR_OP, dxor_block.groups()[0])
        self._xor_strings = list(
            filter(
                None,
                [
                    self._payload.user_string_from_rva(bytes_to_int(rva))
                    for rva in xor_string_rvas
                ],
            )
        )
        logger.debug(f"{len(self._xor_strings)} XOR strings found")

        # Get the static constructor containing the XOR key
        xor_key_cctor = self._payload.method_from_instruction_offset(
            dxor_block.start(), step=1, by_token=True
        )
        xor_key_cctor_body = self._payload.method_body_from_method(xor_key_cctor)

        # Derive the XOR key RVA and value
        xor_rva = search(PATTERN_LDSTR_OP, xor_key_cctor_body)
        if xor_rva is None:
            raise ConfigParserException("Could not identify XOR key RVA")
        xor_rva = bytes_to_int(xor_rva.groups()[0])
        self.key = bytes(self._payload.user_string_from_rva(xor_rva), encoding="utf-8")
        logger.debug(f"XOR key found at {hex(xor_rva)} : {self.key}")
