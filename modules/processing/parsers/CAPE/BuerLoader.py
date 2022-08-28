# Copyright (C) 2021 Kevin O'Reilly kevoreilly@gmail.com
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

import pefile

DESCRIPTION = "BuerLoader configuration parser."
AUTHOR = "kevoreilly"
rule_source = """
rule BuerLoader
{
    meta:
        author = "kevoreilly & Rony (@r0ny_123)"
        cape_type = "BuerLoader Payload"
    strings:
        $trap = {0F 31 89 45 ?? 6A 00 8D 45 ?? 8B CB 50 E8 [4] 0F 31}
        $decode = {8A 0E 84 C9 74 0E 8B D0 2A 0F 46 88 0A 42 8A 0E 84 C9 75 F4 5F 5E 5D C2 04 00}
        $op = {33 C0 85 D2 7E 1? 3B C7 7D [0-15] 40 3B C2 7C ?? EB 02}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"""


def decrypt_string(string):
    return "".join(chr(ord(char) - 6) for char in string)


def extract_config(filebuf):
    cfg = {}
    pe = pefile.PE(data=filebuf)
    data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
    if not data_sections:
        return None
    data = data_sections[0].get_data()
    for item in data.split(b"\x00\x00"):
        try:
            dec = decrypt_string(item.lstrip(b"\x00").rstrip(b"\x00").decode())
            if "dll" not in dec and " " not in dec and ";" not in dec and "." in dec:
                cfg["other"] = {"address": dec}
        except Exception:
            pass
    if cfg:
        cfg["family"] = "BuerLoader"
    return cfg
