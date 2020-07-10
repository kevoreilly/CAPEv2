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

from mwcp.parser import Parser
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


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "ChChes":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
    return addresses


def string_from_offset(data, offset):
    string = data[offset : offset + MAX_STRING_SIZE].split(b"\0")[0]
    return string


class ChChes(Parser):

    DESCRIPTION = "ChChes configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data

        type1 = yara_scan(filebuf, "$payload1")
        type2 = yara_scan(filebuf, "$payload2")
        type3 = yara_scan(filebuf, "$payload3")
        type4 = yara_scan(filebuf, "$payload4")

        if type1:
            c2_offset = 0xE455

            c2_url = string_from_offset(filebuf, c2_offset)
            if c2_url:
                self.reporter.add_metadata("c2_url", c2_url)

        if type2:
            c2_offset = 0xED55

            c2_url = string_from_offset(filebuf, c2_offset)
            if c2_url:
                self.reporter.add_metadata("c2_url", c2_url)

        if type3:
            c2_offset = 0xE2B9

            c2_url = string_from_offset(filebuf, c2_offset)
            if c2_url:
                self.reporter.add_metadata("c2_url", c2_url)

        # no c2 for type4
