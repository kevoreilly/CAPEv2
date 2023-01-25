# Copyright (C) 2021 kevoreilly, enzo
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
from contextlib import suppress

import pefile


def extract_config(filebuf):
    cfg = {}
    pe = None
    with suppress(Exception):
        pe = pefile.PE(data=filebuf, fast_load=False)
    if pe is None:
        return
    for section in pe.sections:
        if section.Name == b".d\x00\x00\x00\x00\x00\x00":
            config_section = bytearray(section.get_data())
            dec = []
            for n, x in enumerate(config_section):
                k = x ^ config_section[n + 64]
                dec.append(k)
                if n > 32:
                    break
            campaign, c2 = struct.unpack("I30s", bytes(dec))
            cfg["C2"] = c2.split(b"\00", 1)[0].decode()
            cfg["Campaign"] = campaign
            return cfg


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
