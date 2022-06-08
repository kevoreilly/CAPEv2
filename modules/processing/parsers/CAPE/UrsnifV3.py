# Copyright (C) 2017 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import binascii
import struct

from Cryptodome.PublicKey import RSA

MAX_STRING_SIZE = 256

# JOINER_SECTIONS = {
#     0xE1285E64: "CRC_PUBLIC_KEY",
#     0x8FB1DDE1: "CRC_CLIENT_INI",
#     0xD722AFCB: "CRC_CLIENT_INI",
#     0x4F75CEA7: "CRC_LOADER_DLL",
#     0x90F8AAB5: "CRC_LOADER_DLL",
#     0x7A042A8A: "CRC_INSTALL_INI",
#     0x90F8AAB4: "CRC_CLIENT64",
#     0xDA57D71A: "CRC_WORDLIST",
#     0xC535D8BF: "CRC_LOADER_DLL",
# }

# INI_PARAMS = {
#     0x4FA8693E: "CRC_SERVERKEY",
#     0xD0665BF6: "CRC_HOSTS",
#     0x656B798A: "CRC_GROUP",
#     0x556AED8F: "CRC_SERVER",
#     0x11271C7F: "CONF_TIMEOUT",
#     0x48295783: "CONFIG_FAIL_TIMEOUT",
#     0xEA9EA760: "CRC_BOOTSTRAP",
#     0x31277BD5: "CRC_TASKTIMEOUT",
#     0x955879A6: "CRC_SENDTIMEOUT",
#     0x9FD13931: "CRC_BCSERVER",
#     0x6DE85128: "CRC_BCTIMEOUT",
#     0xACC79A02: "CRC_KNOCKERTIMEOUT",
#     0x602C2C26: "CRC_KEYLOGLIST",
#     0xD7A003C9: "CRC_CONFIGTIMEOUT",
#     0x18A632BB: "CRC_CONFIGFAILTIMEOUT",
#     0x73177345: "CRC_DGA_SEED_URL",
#     0x510F22D2: "CRC_TORSERVER",
#     0xEC99DF2E: "CRC_EXTERNALIP",
#     0xC61EFA7A: "CRC_DGATLDS",
#     0xDF351E24: "CRC_32BITDOWNLOAD",
#     0x4B214F54: "CRC_64BITDOWNLOAD",
#     0xCD850E68: "DGA_CRC",
#     0xDF2E7488: "DGA_COUNT",
#     0x584E5925: "TIMER",
# }

SECTION_KEYS = {
    0xD0665BF6: "Domains",
    0x73177345: "DGA Base URL",
    0xCD850E68: "DGA CRC",
    0xC61EFA7A: "DGA TLDs",
    0x510F22D2: "TOR Domains",
    0xDF351E24: "32-bit DLL URLs",
    0x4B214F54: "64-bit DLL URLs",
    0xEC99DF2E: "IP Service",
    0x11271C7F: "Timer",
    0xDF2E7488: "DGA count",
    0x556AED8F: "Server",
    0x4FA8693E: "Encryption key",
    0xD7A003C9: "Config Fail Timeout",
    0x18A632BB: "Config Timeout",
    0x31277BD5: "Task Timeout",
    0x955879A6: "Send Timeout",
    0xACC79A02: "Knocker Timeout",
    0x6DE85128: "BC Timeout",
    0x656B798A: "Botnet ID",
    0xEFC574AE: "Value 11",
    # 0x584E5925: 'EndPointer',
    0xD3AA96D0: "New unknown",
}


def string_from_offset(buffer, offset):
    return buffer[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0].decode()


def get_config_item(config, offset):
    config_string = string_from_offset(config, offset)
    return config_string.split(" ") if " " in config_string else config_string


def convert_pubkey(pub):
    # bit = struct.unpack_from('<I', pub)[0]
    bit = 0x200
    mod = pub[4 : (bit / 8) + 4]
    exp = pub[(bit / 8) + 4 :]

    mod = int(binascii.hexlify(mod), 16)
    exp = int(binascii.hexlify(exp), 16)
    keypub = RSA.construct((mod, int(exp)))
    pempub = keypub.exportKey("PEM")
    return keypub, pempub


def extract_config(raw_data):
    config_dict = {}

    if len(raw_data) == 132:
        keypub, pempub = convert_pubkey(raw_data)
        config_dict["RSA public key"] = pempub
        return config_dict

    dword1 = struct.unpack("I", raw_data[:4])[0]
    dword2 = struct.unpack("I", raw_data[4:8])[0]

    if dword1 < 0x40:
        number_of_sections = dword1
        section_count = 0
        section_offset = 8
        while section_count < number_of_sections:
            section_key = struct.unpack("I", raw_data[section_offset : section_offset + 4])[0]
            section_type = struct.unpack("I", raw_data[section_offset + 4 : section_offset + 8])[0]
            if section_type == 1:
                data_offset = struct.unpack("I", raw_data[section_offset + 8 : section_offset + 12])[0]
                config_item = get_config_item(raw_data, section_offset + data_offset)
                if config_item == "":
                    section_count += 1
                    section_offset += 24
                    continue
                option = SECTION_KEYS.get(section_key)
                if option:
                    config_dict[option] = config_item

            section_count += 1
            section_offset += 24

    elif dword2 == 0:
        section_offset = 8
        section_key = struct.unpack("I", raw_data[section_offset : section_offset + 4])[0]
        section_type = struct.unpack("I", raw_data[section_offset + 4 : section_offset + 8])[0]
        while section_type == 1:
            section_key = struct.unpack("I", raw_data[section_offset : section_offset + 4])[0]
            section_type = struct.unpack("I", raw_data[section_offset + 4 : section_offset + 8])[0]
            data_offset = struct.unpack("I", raw_data[section_offset + 8 : section_offset + 12])[0]
            config_item = get_config_item(raw_data, section_offset + data_offset)
            if config_item == "":
                section_offset += 24
                continue
            option = SECTION_KEYS.get(section_key)
            if option:
                config_dict[option] = config_item
            section_offset += 24

    return config_dict
