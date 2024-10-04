#!/usr/bin/env python3
#
# config_decryptor_random_hardcoded.py
#
# Author: jeFF0Falltrades
#
# Provides a custom decryptor for RAT payloads utilizing the method of
# randomly selecting from an embedded list of C2 domains/supradomains
#
# Example hash: a2817702fecb280069f0723cd2d0bfdca63763b9cdc833941c4f33bbe383d93e
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
from ..data_utils import bytes_to_int
from ..dotnet_constants import PATTERN_LDSTR_OP
from ..dotnetpe_payload import DotNetPEMethod, DotNetPEPayload
from .config_decryptor import ConfigDecryptor, IncompatibleDecryptorException
from .config_decryptor_plaintext import ConfigDecryptorPlaintext

logger = getLogger(__name__)


class ConfigDecryptorRandomHardcoded(ConfigDecryptor):
    _KEY_HARDCODED_HOSTS = "hardcoded_hosts"

    # Pattern to find the Method that retrieves a random domain
    _PATTERN_RANDOM_DOMAIN = compile(
        rb"(?:\x73.{3}\x0a){2}\x25.+?\x0a\x06(?:\x6f.{3}\x0a){2}\x0b", flags=DOTALL
    )

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)
        try:
            self._random_domain_method = self._get_random_domain_method()
        except Exception as e:
            raise IncompatibleDecryptorException(e)

    # Returns a combined config containing config fields + hardcoded hosts
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, list[str] | str]:
        config = {}
        # Pass off plaintext config to a ConfigDecryptorPlaintext
        ptcd = ConfigDecryptorPlaintext(self._payload)
        config.update(ptcd.decrypt_encrypted_strings(encrypted_strings))
        config[self._KEY_HARDCODED_HOSTS] = self._get_hardcoded_hosts()
        return config

    # Retrieves and returns a list of hardcoded hosts
    def _get_hardcoded_hosts(self) -> list[str]:
        random_domain_method_body = self._payload.method_body_from_method(
            self._random_domain_method
        )
        hardcoded_host_rvas = findall(PATTERN_LDSTR_OP, random_domain_method_body)

        hardcoded_hosts = []
        for rva in hardcoded_host_rvas:
            try:
                harcoded_host = self._payload.user_string_from_rva(bytes_to_int(rva))
                if harcoded_host != ".":
                    hardcoded_hosts.append(harcoded_host)
            except Exception as e:
                logger.error(f"Error translating hardcoded host at {hex(rva)}: {e}")
                continue

        logger.debug(f"Hardcoded hosts found: {hardcoded_hosts}")
        return hardcoded_hosts

    # Retrieves the Method that randomly selects from a list of embedded hosts
    def _get_random_domain_method(self) -> DotNetPEMethod:
        logger.debug("Searching for random domain method")
        random_domain_marker = search(self._PATTERN_RANDOM_DOMAIN, self._payload.data)
        if random_domain_marker is None:
            raise ConfigParserException(
                "Could not identify random domain generator method"
            )

        random_domain_method = self._payload.method_from_instruction_offset(
            random_domain_marker.start()
        )

        logger.debug(
            f"Random domain generator found at offset {hex(random_domain_method.offset)}"
        )
        return random_domain_method
