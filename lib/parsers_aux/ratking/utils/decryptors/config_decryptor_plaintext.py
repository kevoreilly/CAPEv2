#!/usr/bin/env python3
#
# config_decryptor_plaintext.py
#
# Author: jeFF0Falltrades
#
# Provides a fall-through decryptor that will attempt to return the plaintext
# values of a found config when all other decryptors fail
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

from .config_decryptor import ConfigDecryptor

logger = getLogger(__name__)


class ConfigDecryptorPlaintext(ConfigDecryptor):
    def __init__(self, payload, config_strings):
        super().__init__(payload, config_strings)

    def decrypt(self, ciphertext):
        return ciphertext

    def decrypt_encrypted_strings(self):
        logger.debug("Could not find applicable decryptor, returning found config as plaintext...")
        return self.config_strings
