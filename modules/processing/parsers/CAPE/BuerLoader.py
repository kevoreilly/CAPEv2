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


def decrypt_string(string):
    enc = []
    for char in string:
        enc.append(chr(ord(char) - 6))
    return "".join(enc)


def config(filebuf):
    cfg = {}
    pe = pefile.PE(data=filebuf)
    data_sections = [s for s in pe.sections if s.Name.find(b".data") != -1]
    if not data_sections:
        return None
    data = data_sections[0].get_data()
    count = 0
    for item in data.split(b"\x00\x00"):
        try:
            dec = decrypt_string(item.lstrip(b"\x00").rstrip(b"\x00").decode())
        except:
            pass
        if "dll" not in dec and " " not in dec and ";" not in dec and "." in dec:
            cfg.setdefault("address", []).append(dec)
        return cfg
