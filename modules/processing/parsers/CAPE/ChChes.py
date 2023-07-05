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
DESCRIPTION = "ChChes configuration parser."
AUTHOR = "kevoreilly"

import yara

rule_source = """
rule ChChes
{
    meta:
        author = "kev"
        description = "ChChes Payload"
        cape_type = "ChChes Payload"
    strings:
        $payload1 = {55 8B EC 53 E8 EB FC FF FF E8 DB FF FF FF 05 10 FE 2A 00 33 DB 39 58 44 75 58 56 57 50 E8 57 00 00 00 59 8B F0 E8 AB FF FF FF B9 01 1F 2A 00 BF D0 1C 2A 00 2B CF 03 C1 39 5E 30 76 0F}
        $payload2 = {55 8B EC 53 E8 8F FB FF FF E8 DB FF FF FF 05 00 07 FF 00 33 DB 39 58 44 75 58 56 57 50 E8 57 00 00 00 59 8B F0 E8 AB FF FF FF B9 5D 20 FE 00 BF D0 1C FE 00 2B CF 03 C1 39 5E 30 76 0F }
        $payload3 = {55 8B EC 53 E8 E6 FC FF FF E8 DA FF FF FF 05 80 FC FC 00 33 DB 39 58 44 75 58 56 57 50 E8 57 00 00 00 59 8B F0 E8 AA FF FF FF B9 05 1F FC 00 BF D0 1C FC 00 2B CF 03 C1 39 5E 30 76 0F}
        $payload4 = {55 8B EC E8 ?? ?? FF FF E8 D? FF FF FF 05 ?? ?? ?? 00 83 78 44 00 75 40 56 57 50 E8 3E 00 00 00 59 8B F0 6A 00 FF 76 30 E8 A8 FF FF FF B9 ?? ?? ?? 00 BF 00 1A E1 00 2B CF 03 C1 50 FF 56 70}
    condition:
        $payload1 or $payload2 or $payload3 or $payload4
}
"""

MAX_STRING_SIZE = 128


def yara_scan(raw_data):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule != "ChChes":
            continue

        for block in match.strings:
            for instance in block.instances:
                addresses[block.identifier] = instance.offset
    return addresses


def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


def extract_config(filebuf):
    tmp_config = {}
    yara_matches = yara_scan(filebuf)

    c2_offsets = []
    if yara_matches.get("$payload1"):
        c2_offsets.append(0xE455)
    if yara_matches.get("$payload2"):
        c2_offsets.append(0xED55)
    if yara_matches.get("$payload3"):
        c2_offsets.append(0xE2B9)
    # no c2 for type4

    for c2_offset in c2_offsets:
        c2_url = string_from_offset(filebuf, c2_offset)
        if c2_url:
            tmp_config.setdefault("c2_url", []).append(c2_url)

    return tmp_config
