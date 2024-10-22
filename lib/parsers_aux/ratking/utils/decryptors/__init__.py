#!/usr/bin/env python3
#
# __init__.py
#
# Author: jeFF0Falltrades
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
from .config_decryptor import ConfigDecryptor, IncompatibleDecryptorException
from .config_decryptor_aes_cbc import ConfigDecryptorAESCBC
from .config_decryptor_aes_ecb import ConfigDecryptorAESECB
from .config_decryptor_decrypt_xor import ConfigDecryptorDecryptXOR
from .config_decryptor_plaintext import ConfigDecryptorPlaintext
from .config_decryptor_random_hardcoded import ConfigDecryptorRandomHardcoded

__all__ = [
    ConfigDecryptor,
    IncompatibleDecryptorException,
    ConfigDecryptorAESCBC,
    ConfigDecryptorAESECB,
    ConfigDecryptorDecryptXOR,
    ConfigDecryptorRandomHardcoded,
    ConfigDecryptorPlaintext,
]

# ConfigDecryptorPlaintext should always be the last fallthrough case
SUPPORTED_DECRYPTORS = [
    ConfigDecryptorAESCBC,
    ConfigDecryptorAESECB,
    ConfigDecryptorDecryptXOR,
    ConfigDecryptorRandomHardcoded,
    ConfigDecryptorPlaintext,
]
