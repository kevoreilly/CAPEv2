#!/usr/bin/env python3
#
# config_decryptor_aes_ecb.py
#
# Author: jeFF0Falltrades
#
# Provides a custom AES decryptor for RAT payloads utilizing ECB mode
#
# Example Hash: d5028e10a756f2df677f32ebde105d7de8df37e253c431837c8f810260f4428e
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
from base64 import b64decode
from hashlib import md5
from logging import getLogger
from re import DOTALL, compile, search

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.padding import PKCS7

from ...config_parser_exception import ConfigParserException
from ..data_utils import bytes_to_int, decode_bytes
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import ConfigDecryptor, IncompatibleDecryptorException

logger = getLogger(__name__)


class ConfigDecryptorAESECB(ConfigDecryptor):
    # MD5 hash pattern used to detect AES key
    _PATTERN_MD5_HASH = compile(rb"\x7e(.{3}\x04)\x28.{3}\x06\x6f", DOTALL)

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        try:
            self._aes_key_rva = self._get_aes_key_rva()
        except Exception as e:
            raise IncompatibleDecryptorException(e)

    # Given ciphertext, creates a Cipher object with the AES key and decrypts
    # the ciphertext
    def _decrypt(self, ciphertext: bytes) -> bytes:
        logger.debug(f"Decrypting {ciphertext} with key {self.key.hex()}...")
        aes_cipher = Cipher(AES(self.key), ECB(), backend=default_backend())
        decryptor = aes_cipher.decryptor()
        unpadder = PKCS7(AES.block_size).unpadder()
        # Use a PKCS7 unpadder to remove padding from decrypted value
        # https://cryptography.io/en/latest/hazmat/primitives/padding/
        unpadder = PKCS7(AES.block_size).unpadder()

        try:
            padded_text = decryptor.update(ciphertext) + decryptor.finalize()
            unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        except Exception as e:
            raise ConfigParserException(
                f"Error decrypting ciphertext {ciphertext} with key {self.key.hex()}: {e}"
            )

        logger.debug(f"Decryption result: {unpadded_text}")
        return unpadded_text

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, str]:
        logger.debug("Decrypting encrypted strings...")

        if self.key is None:
            try:
                raw_key_field = self._payload.field_name_from_rva(self._aes_key_rva)
                self.key = self._derive_aes_key(encrypted_strings[raw_key_field])
            except Exception as e:
                raise ConfigParserException(f"Failed to derive AES key: {e}")

        decrypted_config_strings = {}
        for k, v in encrypted_strings.items():
            # Leave empty strings as they are
            if len(v) == 0:
                logger.debug(f"Key: {k}, Value: {v}")
                decrypted_config_strings[k] = v
                continue

            # Check if base64-encoded string
            b64_exception = False
            try:
                decoded_val = b64decode(v)
            except Exception:
                b64_exception = True
            # If it was not base64-encoded, leave the value as it is
            if b64_exception:
                logger.debug(f"Key: {k}, Value: {v}")
                decrypted_config_strings[k] = v
                continue

            ciphertext = decoded_val
            result, last_exc = None, None
            try:
                result = decode_bytes(self._decrypt(ciphertext))
            except ConfigParserException as e:
                last_exc = e

            if result is None:
                logger.debug(f"Decryption failed for item {v}: {last_exc}")
                result = v

            logger.debug(f"Key: {k}, Value: {result}")
            decrypted_config_strings[k] = result

        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Given the raw bytes that will become the key value, derives the AES key
    def _derive_aes_key(self, key_unhashed: str) -> bytes:
        # Generate the MD5 hash
        md5_hash = md5()
        md5_hash.update(key_unhashed.encode("utf-8"))
        md5_digest = md5_hash.digest()

        # Key is a 32-byte value made up of the MD5 hash overlaying itself,
        # tailed with one null byte
        key = md5_digest[:15] + md5_digest[:16] + b"\x00"
        logger.debug(f"AES key derived: {key}")
        return key

    # Extracts the AES key RVA from the payload
    def _get_aes_key_rva(self) -> int:
        logger.debug("Extracting AES key value...")
        key_hit = search(self._PATTERN_MD5_HASH, self._payload.data)
        if key_hit is None:
            raise ConfigParserException("Could not find AES key pattern")

        key_rva = bytes_to_int(key_hit.groups()[0])
        logger.debug(f"AES key RVA: {hex(key_rva)}")
        return key_rva
