# Copyright (C) 2015 Kevin O'Reilly kevin.oreilly@contextis.co.uk
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

DESCRIPTION = "Enfal configuration parser."
AUTHOR = "kevoreilly"

import yara

rule_source = """
rule Enfal
{
    meta:
        author = "kev"
        description = "Enfal configuration blob"
        cape_type = "Enfal Config"
    strings:
        $config = {BF 49 ?? 75 22 12 ?? 75 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

    condition:
        $config
}
"""

MAX_STRING_SIZE = 128


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Enfal":
            for item in match.strings:
                if item.identifier == rule_name:
                    addresses[item.identifier] = item.instances[0].offset
    return addresses


def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


def list_from_offset(data, offset):
    string = data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]
    return string.split(b",")


def extract_config(filebuf):
    config = yara_scan(filebuf, "$config")
    return_conf = {}
    if config:
        yara_offset = int(config["$config"])

        c2_address = string_from_offset(filebuf, yara_offset + 0x2E8)
        if c2_address:
            return_conf["c2_address"] = c2_address

        c2_url = string_from_offset(filebuf, yara_offset + 0xE8)
        if c2_url:
            return_conf["c2_url"] = c2_url

        if filebuf[yara_offset + 0x13B0 : yara_offset + 0x13B1] == "S":
            registrypath = string_from_offset(filebuf, yara_offset + 0x13B0)
        elif filebuf[yara_offset + 0x13C0 : yara_offset + 0x13C1] == "S":
            registrypath = string_from_offset(filebuf, yara_offset + 0x13C0)
        elif filebuf[yara_offset + 0x13D0 : yara_offset + 0x13D1] == "S":
            registrypath = string_from_offset(filebuf, yara_offset + 0x13D0)
        else:
            registrypath = ""

        if registrypath:
            return_conf["registrypath"] = registrypath

        if filebuf[yara_offset + 0x14A2 : yara_offset + 0x14A3] == "C":
            servicename = ""
            filepaths = list_from_offset(filebuf, yara_offset + 0x14A2)
            filepaths[0] = filepaths[0].split(b" ", 1)[0]
        elif filebuf[yara_offset + 0x14B0 : yara_offset + 0x14B1] != "\0":
            servicename = string_from_offset(filebuf, yara_offset + 0x14B0)
            filepaths = list_from_offset(filebuf, yara_offset + 0x14C0)
        elif filebuf[yara_offset + 0x14C0 : yara_offset + 0x14C1] != "\0":
            servicename = string_from_offset(filebuf, yara_offset + 0x14C0)
            filepaths = list_from_offset(filebuf, yara_offset + 0x14D0)
        elif filebuf[yara_offset + 0x14D0 : yara_offset + 0x14D1] != "\0":
            servicename = string_from_offset(filebuf, yara_offset + 0x14D0)
            filepaths = list_from_offset(filebuf, yara_offset + 0x14E0)
        else:
            servicename = ""
            filepaths = []

        if servicename:
            return_conf["servicename"] = servicename
        if filepaths:
            for path in filepaths:
                return_conf.setdefault("filepath", []).append(path)
