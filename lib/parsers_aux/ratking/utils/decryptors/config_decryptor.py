#!/usr/bin/env python3
#
# config_decryptor.py
#
# Author: jeFF0Falltrades
#
# Provides a simple abstract base class for different types of config decryptors
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

from ..dotnetpe_payload import DotNetPEPayload

logger = getLogger(__name__)


# Custom Exception to denote that a decryptor is incompatible with a payload
class IncompatibleDecryptorException(Exception):
    pass


class ConfigDecryptor(ABC):
    def __init__(self, payload: DotNetPEPayload) -> None:
        self.key: bytes | str = None
        self._payload = payload
        self.salt: bytes = None

    # Abstract method to take in a map representing a configuration of config
    # Field names and values and return a decoded/decrypted configuration
    @abstractmethod
    def decrypt_encrypted_strings(
        self, encrypted_strings: dict[str, str]
    ) -> dict[str, list[str] | str]:
        pass
