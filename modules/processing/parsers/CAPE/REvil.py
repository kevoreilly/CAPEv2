# Copyright (C) 2019 R3MRUM (https://twitter.com/R3MRUM)
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

#!/usr/bin/python

import json
import struct

import pefile


def getSectionNames(sections):
    return [section.Name.partition(b"\0")[0] for section in sections]


def getREvilKeyAndConfig(pesections, section_name):
    for section in pesections:
        if section.Name.partition(b"\0")[0] == section_name:
            data = section.get_data()
            if len(data) > 32:
                key = data[:32]
                encoded_config = data[32:]
                return key, encoded_config


def decodeREvilConfig(config_key, config_data):
    init255 = list(range(256))

    key = config_key
    config_len = struct.unpack("<H", config_data[4:6])[0]
    encoded_config = config_data[8 : config_len + 7]
    decoded_config = []

    # print(f"Key:\t{key}")

    ECX = EAX = ESI = 0

    for char in init255:
        ESI = ((char & 0xFF) + (ord(key[EAX % len(key)]) + ESI)) & 0xFF
        init255[EAX] = init255[ESI] & 0xFF
        EAX += 1
        init255[ESI] = char & 0xFF

    EAX = ESI = 0

    for char in encoded_config:
        ECX = (EAX + 1) & 0xFF
        LOCAL1 = ECX
        DL = init255[ECX]
        ESI = (ESI + DL) & 0xFF
        init255[ECX] = init255[ESI]
        init255[ESI] = DL
        decoded_config.append((init255[((init255[ECX] + DL) & 0xFF)]) ^ ord(char))
        EAX = LOCAL1

    return json.loads("".join(map(chr, decoded_config)))


def extract_config(data):
    config_data = ""
    config_key = ""
    pe = pefile.PE(data=data)

    if len(pe.sections) == 5:
        section_names = getSectionNames(pe.sections)
        required_sections = (".text", ".rdata", ".data", ".reloc")

        # print section_names
        if all(sections in section_names for sections in required_sections):
            # print("all required section names found")
            config_section_name = [resource for resource in section_names if resource not in required_sections][0]
            config_key, config_data = getREvilKeyAndConfig(pe.sections, config_section_name)
            if config_key and config_data:
                return decodeREvilConfig(config_key, config_data)
