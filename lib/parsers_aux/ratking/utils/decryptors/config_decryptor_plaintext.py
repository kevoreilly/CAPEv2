#!/usr/bin/env python3
#
# config_decryptor_plaintext.py
#
# Author: jeFF0Falltrades
#
# Provides a fall-through decryptor that will attempt to return the plaintext
# values of a found config when all other decryptors fail by matching known
# config field names from supported RAT families
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

from ...config_parser_exception import ConfigParserException
from ..dotnetpe_payload import DotNetPEPayload
from .config_decryptor import ConfigDecryptor

logger = getLogger(__name__)

KNOWN_CONFIG_FIELD_NAMES = set(
    [
        "AUTHKEY",
        "An_ti",
        "Anti",
        "Anti_Process",
        "BDOS",
        "BS_OD",
        "Certifi_cate",
        "Certificate",
        "DIRECTORY",
        "De_lay",
        "Delay",
        "DoStartup",
        "ENABLELOGGER",
        "EncryptionKey",
        "Groub",
        "Group",
        "HIDEFILE",
        "HIDEINSTALLSUBDIRECTORY",
        "HIDELOGDIRECTORY",
        "HOSTS",
        "Hos_ts",
        "Hosts",
        "Hw_id",
        "Hwid",
        "INSTALL",
        "INSTALLNAME",
        "In_stall",
        "Install",
        "InstallDir",
        "InstallFile",
        "InstallFolder",
        "InstallStr",
        "Install_File",
        "Install_Folder",
        "Install_path",
        "KEY",
        "Key",
        "LOGDIRECTORYNAME",
        "MTX",
        "MUTEX",
        "Mutex",
        "Paste_bin",
        "Pastebin",
        "Por_ts",
        "Port",
        "Ports",
        "RECONNECTDELAY",
        "SPL",
        "STARTUP",
        "STARTUPKEY",
        "SUBDIRECTORY",
        "ServerIp",
        "ServerPort",
        "Server_signa_ture",
        "Serversignature",
        "Sleep",
        "TAG",
        "USBNM",
        "VERSION",
        "Ver_sion",
        "Version",
        "delay",
        "mutex_string",
        "startup_name",
    ]
)


class ConfigDecryptorPlaintext(ConfigDecryptor):
    # Minimum threshold for matching Field names
    MIN_THRESHOLD_MATCH = 3

    def __init__(self, payload: DotNetPEPayload) -> None:
        super().__init__(payload)

    # Calculates whether the config meets the minimum threshold for known Field
    # Names and returns it if it does
    def decrypt_encrypted_strings(self, encrypted_strings: dict[str, str]) -> dict[str, str]:
        field_names = set(encrypted_strings.keys())
        num_overlapping_field_names = len(KNOWN_CONFIG_FIELD_NAMES & field_names)
        if num_overlapping_field_names < self.MIN_THRESHOLD_MATCH:
            raise ConfigParserException("Plaintext threshold of known config items not met")
        return encrypted_strings
