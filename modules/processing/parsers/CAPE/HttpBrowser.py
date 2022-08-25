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

import struct

import pefile
import yara

DESCRIPTION = "HttpBrowser configuration parser."
AUTHOR = "kevoreilly"


rule_source = """
rule HttpBrowser
{
    meta:
        author = "kev"
        description = "HttpBrowser C2 connect function"
        cape_type = "HttpBrowser Payload"
    strings:
        $connect_1 = {33 C0 68 06 02 00 00 66 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 5? 50 E8 ?? ?? 00 00 8B 35 ?? ?? ?? ?? 83 C4 0C 6A 01 BB ?? ?? ?? ?? 53 FF D6 59 50 BF}
        $connect_2 = {33 C0 68 06 02 00 00 66 89 ?? ?? ?? 8D ?? ?? ?? 5? 50 E8 ?? ?? 00 00 8B 35 ?? ?? ?? ?? 83 C4 0C 6A 01 BB ?? ?? ?? ?? 53 FF D6 59 50 BF}
        $connect_3 = {68 40 1F 00 00 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? BB ?? ?? ?? ?? 53 FF D6 59 50 BF ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 59 59}
        $connect_4 = {33 C0 57 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 6A 01 FF 75 08 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        $connect_1 or $connect_2 or $connect_3 or $connect_4
}
"""

MAX_STRING_SIZE = 67


def yara_scan(raw_data):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "HttpBrowser":
            for item in match.strings:
                addresses[item[1]] = item[0]
    return addresses


def pe_data(pe, va, size):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    return pe.get_data(rva, size)


def ascii_from_va(pe, offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    string_rva = struct.unpack("i", pe.__data__[offset: offset + 4])[0] - image_base
    string_offset = pe.get_offset_from_rva(string_rva)
    return pe.__data__[string_offset: string_offset + MAX_STRING_SIZE].split(b"\0", 1)[0]


def unicode_from_va(pe, offset):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    string_rva = struct.unpack("i", pe.__data__[offset: offset + 4])[0] - image_base
    string_offset = pe.get_offset_from_rva(string_rva)
    return pe.__data__[string_offset: string_offset + MAX_STRING_SIZE].split(b"\x00\x00", 1)[0]


match_map = {
    "$connect_1": [39, 49],
    "$connect_2": [35, 45],
    "$connect_3": [18, 28, 66],
    "$connect_4": [35, 90, 13],
}


def extract_config(filebuf):
    pe = pefile.PE(data=filebuf, fast_load=True)
    # image_base = pe.OPTIONAL_HEADER.ImageBase

    yara_matches = yara_scan(filebuf)
    tmp_config = {"family": "HTTPBrowser"}
    tcp_connections = []
    for key, values in match_map.keys():
        if yara_matches.get(key):
            yara_offset = int(yara_matches[key])
            if key in ("$connect_1", "$connect_2", "$connect_3"):
                port = ascii_from_va(pe, yara_offset + values[0])

                c2_address = unicode_from_va(pe, yara_offset + values[1])
                if c2_address:
                    tcp_conn = {"server_ip": c2_address, "usage": "c2"}
                    if port:
                        tcp_conn["server_port"] = port
                    tcp_connections.append(tcp_conn)

                if key == "$connect_3":
                    c2_address = unicode_from_va(pe, yara_offset + values[2])
                    if c2_address:
                        tcp_conn = {"server_ip": c2_address, "usage": "c2"}
                        if port:
                            tcp_conn["server_port"] = port
                        tcp_connections.append(tcp_conn)
            else:
                c2_address = unicode_from_va(pe, yara_offset + values[0])
                if c2_address:
                    tcp_connections.append({"server_ip": c2_address, "usage": "c2"})

                filepath = unicode_from_va(pe, yara_offset + values[1])
                if filepath:
                    tmp_config["paths"] = [{"path": filepath, "usage": "c2"}]

                injectionprocess = unicode_from_va(pe, yara_offset - values[2])
                if injectionprocess:
                    tmp_config["inject_exe"] = [injectionprocess]

    if tcp_connections:
        tmp_config["tcp"] = tcp_connections

    return tmp_config
