# Copyright (C) 2024 enzok
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


import datetime
import re
from contextlib import suppress

import pefile


def get_current_year() -> str:
    current_date = datetime.datetime.now()
    return str(current_date.year)


def decrypt_string(encoded_string: str, key: str) -> str:
    encoded_bytes = bytearray.fromhex(encoded_string)
    key_bytes = bytearray(ord(char) for char in key)
    encoded_length = len(encoded_bytes)
    key_length = len(key_bytes)
    decoded_bytes = bytearray(encoded_length)

    for i in range(encoded_length):
        new_byte = (encoded_bytes[i] ^ key_bytes[i % key_length]) & 0xFF
        decoded_bytes[i] = new_byte

    decoded_string = decoded_bytes.decode("ascii", errors="ignore")

    return decoded_string


def extract_config(data: bytes) -> dict:
    pe = pefile.PE(data=data)
    rdata_section = None
    for section in pe.sections:
        if b".rdata" in section.Name:
            rdata_section = section
            break

    if not rdata_section:
        return {}

    rdata_data = rdata_section.get_data()
    patterns = [b"Builder\.dll\x00", b"Builder\.exe\x00"]
    matches = []
    for pattern in patterns:
        matches.extend(re.finditer(pattern, rdata_data))

    found_strings = set()
    for match in matches:
        start = max(0, match.start() - 1024)
        end = min(len(rdata_data), match.end() + 1024)
        found_strings.update(re.findall(b"[\x20-\x7E]{4,}?\x00", rdata_data[start:end]))

    result = {}
    urls = []
    directories = []
    campaign = ""

    if found_strings:
        for string in found_strings:
            with suppress(UnicodeDecodeError):
                decoded_string = string.decode("utf-8").rstrip("\x00")

            if re.match(r"^[0-9A-Fa-f]+$", decoded_string):
                key = get_current_year()
                url = decrypt_string(decoded_string, key)
                if url:
                    urls.append(url)
            elif decoded_string.count("\\") > 1:
                directories.append(decoded_string)
            elif re.match(r"^(?![A-Z]{6,}$)[a-zA-Z0-9\-=]{6,}$", decoded_string):
                campaign = decoded_string

        result = {"urls": sorted(urls), "directories": directories, "campaign": campaign}

    return result


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
