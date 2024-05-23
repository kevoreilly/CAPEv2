#!/usr/bin/env python3
#
# config_aes_decryptor.py
#
# Author: jeFF0Falltrades
#
# Provides a custom AES decryptor for RAT payloads utilizing the known
# encryption patterns of AsyncRAT, DcRAT, QuasarRAT, VenomRAT, etc.
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
from .data_utils import bytes_to_int, decode_bytes, int_to_bytes
from .dotnet_constants import OPCODE_LDSTR, OPCODE_LDTOKEN
from base64 import b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from logging import getLogger
from re import DOTALL, search

logger = getLogger(__name__)

MIN_CIPHERTEXT_LEN = 48


class ConfigAESDecryptor:
    PATTERN_AES_KEY_AND_BLOCK_SIZE = (
        b"[\x06-\x09]\x20(.{4})\x6f.{4}[\x06-\x09]\x20(.{4})"
    )
    PATTERN_AES_KEY_BASE = b"(.{3}\x04).%b"
    PATTERN_AES_SALT_ITER = b"[\x02-\x05]\x7e(.{4})\x20(.{4})\x73"
    PATTERN_AES_SALT_INIT = b"\x80%b\x2a"

    def __init__(self, payload, encrypted_config_strings):
        self.payload = payload
        self.encrypted_config_strings = encrypted_config_strings
        self.key_size = self.block_size = self.iterations = self.salt = (
            self.key_candidates
        ) = self.key = None
        self.aes_metadata = self.get_aes_metadata()

    # Given an initialization vector and ciphertext, creates a Cipher
    # object with the AES key and specified IV and decrypts the ciphertext
    def decrypt(self, iv, ciphertext):
        logger.debug(
            f"Decrypting {ciphertext} with key {self.key.hex()} and IV {iv.hex()}..."
        )
        aes_cipher = Cipher(AES(self.key), CBC(iv), backend=default_backend())
        decryptor = aes_cipher.decryptor()
        # Use a PKCS7 unpadder to remove padding from decrypted value
        # https://cryptography.io/en/latest/hazmat/primitives/padding/
        unpadder = PKCS7(self.block_size).unpadder()
        try:
            padded_text = decryptor.update(ciphertext) + decryptor.finalize()
            unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        except Exception as e:
            raise ConfigParserException(
                f"Error decrypting ciphertext {ciphertext} with IV {iv.hex()} and key {self.key.hex()}"
            ) from e
        logger.debug(f"Decryption result: {unpadded_text}")
        return unpadded_text

    # Derives AES passphrase candidates from a config
    # If a passphrase is base64-encoded, both its raw value and decoded value
    # will be added as candidates
    def derive_aes_passphrase_candidates(self, aes_key_rva):
        key_val = self.encrypted_config_strings[aes_key_rva]
        passphrase_candidates = [key_val.encode()]
        try:
            passphrase_candidates.append(b64decode(key_val))
        except Exception:
            pass
        logger.debug(f"AES passphrase candidates found: {passphrase_candidates}")
        return passphrase_candidates

    # Decrypts encrypted config values with the provided cipher data
    def decrypt_encrypted_strings(self):
        logger.debug("Decrypting encrypted strings...")
        decrypted_config_strings = {}
        for k, v in self.encrypted_config_strings.items():
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
            # If it was not base64-encoded, or if it is less than our min length
            # for ciphertext, leave the value as it is
            if b64_exception or len(decoded_val) < MIN_CIPHERTEXT_LEN:
                logger.debug(f"Key: {k}, Value: {v}")
                decrypted_config_strings[k] = v
                continue
            # Otherwise, extract the IV from the 16 bytes after the HMAC
            # (first 32 bytes) and the ciphertext from the rest of the data
            # after the IV, and run the decryption
            iv, ciphertext = decoded_val[32:48], decoded_val[48:]
            result, last_exc = None, None
            key_idx = 0
            # Run through key candidates until suitable one found or failure
            while result is None and key_idx < len(self.key_candidates):
                try:
                    self.key = self.key_candidates[key_idx]
                    key_idx += 1
                    result = decode_bytes(self.decrypt(iv, ciphertext))
                except ConfigParserException as e:
                    last_exc = e
            if result is None:
                logger.debug(
                    f"Decryption failed for item {v}: {last_exc}; Leaving as original value..."
                )
                result = v
            logger.debug(f"Key: {k}, Value: {result}")
            decrypted_config_strings[k] = result
        logger.debug("Successfully decrypted strings")
        return decrypted_config_strings

    # Extracts AES key candidates from the payload
    def get_aes_key_candidates(self, metadata_ins_offset):
        logger.debug("Extracting possible AES key values...")
        keys = []

        # Get the RVA of the method that sets up AES256 metadata
        metadata_method_rva = self.payload.next_method_from_instruction_offset(
            metadata_ins_offset, step_back=1, by_token=True
        )

        # Insert this RVA into the KEY_BASE pattern to find where the AES key
        # is initialized
        key_hit = search(
            self.PATTERN_AES_KEY_BASE % int_to_bytes(metadata_method_rva),
            self.payload.data,
            DOTALL,
        )
        if key_hit is None:
            raise ConfigParserException("Could not find AES key pattern")
        key_rva = bytes_to_int(key_hit.groups()[0])
        logger.debug(f"AES key RVA: {hex(key_rva)}")

        # Since we already have a map of all field names, use the key field
        # name to index into our existing config dict
        passphrase_candidates = self.derive_aes_passphrase_candidates(key_rva)

        for candidate in passphrase_candidates:
            try:
                # The backend parameter is optional in newer versions of the
                # cryptography library, but we keep it here for compatibility
                kdf = PBKDF2HMAC(
                    SHA1(),
                    length=self.key_size,
                    salt=self.salt,
                    iterations=self.iterations,
                    backend=default_backend(),
                )
                keys.append(kdf.derive(candidate))
                logger.debug(f"AES key derived: {keys[-1]}")
            except Exception:
                continue
        if len(keys) == 0:
            raise ConfigParserException(
                f"Could not derive key from passphrase candidates: {passphrase_candidates}"
            )
        return keys

    # Extracts the AES key and block size from the payload
    def get_aes_key_and_block_size(self):
        logger.debug("Extracting AES key and block size...")
        hit = search(self.PATTERN_AES_KEY_AND_BLOCK_SIZE, self.payload.data, DOTALL)
        if hit is None:
            raise ConfigParserException("Could not extract AES key or block size")
        # Convert key size from bits to bytes by dividing by 8
        # Note use of // instead of / to ensure integer output, not float
        key_size = bytes_to_int(hit.groups()[0]) // 8
        block_size = bytes_to_int(hit.groups()[1])
        logger.debug(f"Found key size {key_size} and block size {block_size}")
        return key_size, block_size

    # Identifies the initialization of the AES256 object in the payload
    def get_aes_metadata(self):
        logger.debug("Extracting AES metadata...")
        # Important to use DOTALL here (and with all regex ops to be safe)
        # as we are working with bytes, and if we do not set this, and the
        # byte sequence contains a byte that equates to a newline (\n or 0x0A),
        # the search will fail
        metadata = search(self.PATTERN_AES_SALT_ITER, self.payload.data, DOTALL)
        if metadata is None:
            raise ConfigParserException("Could not identify AES metadata")
        logger.debug(f"AES metadata found at offset {hex(metadata.start())}")

        self.key_size, self.block_size = self.get_aes_key_and_block_size()

        logger.debug("Extracting AES iterations...")
        self.iterations = bytes_to_int(metadata.groups()[1])
        logger.debug(f"Found AES iteration number of {self.iterations}")

        self.salt = self.get_aes_salt(metadata.groups()[0])
        self.key_candidates = self.get_aes_key_candidates(metadata.start())
        return metadata

    # Extracts the AES salt from the payload, accounting for both hardcoded
    # salt byte arrays, and salts derived from hardcoded strings
    def get_aes_salt(self, salt_rva):
        logger.debug("Extracting AES salt value...")
        # Use % to insert our salt RVA into our match pattern
        # This pattern will then find the salt initialization ops,
        # specifically:
        #
        # stsfld	uint8[] Client.Algorithm.Aes256::Salt
        # ret
        aes_salt_initialization = self.payload.data.find(
            self.PATTERN_AES_SALT_INIT % salt_rva
        )
        if aes_salt_initialization == -1:
            raise ConfigParserException("Could not identify AES salt initialization")

        # Look at opcode used to initialize the salt to decide how to
        # proceed on extracting the salt value (start of pattern - 10 bytes)
        salt_op_offset = aes_salt_initialization - 10
        # Need to use bytes([int]) here to properly convert from int to byte
        # string for our comparison below
        salt_op = bytes([self.payload.data[salt_op_offset]])

        # Get the salt RVA from the 4 bytes following the initialization op
        salt_strings_rva_packed = self.payload.data[
            salt_op_offset + 1 : salt_op_offset + 5
        ]
        salt_strings_rva = bytes_to_int(salt_strings_rva_packed)

        # If the op is a ldstr op (0x72), just get the bytes value of the
        # string being used to initialize the salt
        if salt_op == OPCODE_LDSTR:
            salt_encoded = self.payload.user_string_from_rva(salt_strings_rva)
            # We use decode_bytes() here to get the salt string without any
            # null bytes (because it's stored as UTF-16LE), then convert it
            # back to bytes
            salt = decode_bytes(salt_encoded).encode()
        # If the op is a ldtoken (0xd0) operation, we need to get the salt
        # byte array value from the FieldRVA table
        elif salt_op == OPCODE_LDTOKEN:
            salt = self.get_aes_salt_ldtoken_method(salt_strings_rva, salt_op_offset)
        else:
            raise ConfigParserException(f"Unknown salt opcode found: {salt_op.hex()}")
        logger.debug(f"Found salt value: {salt.hex()}")
        return salt

    # Derive the AES salt by loading the RVA of the salt from the FieldRVA
    # table, converting it to a file offset, and reading the salt value from
    # that offset
    def get_aes_salt_ldtoken_method(self, salt_strings_rva, salt_op_offset):
        salt_size = self.payload.data[salt_op_offset - 7]
        salt_field_rva = self.payload.fieldrva_from_rva(salt_strings_rva)
        salt_offset = self.payload.offset_from_rva(salt_field_rva)
        salt_value = self.payload.data[salt_offset : salt_offset + salt_size]
        return salt_value
