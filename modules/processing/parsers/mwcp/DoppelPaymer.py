# Copyright (C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
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
import string
import pefile
import yara
from Crypto.Cipher import ARC4

rule_source = """
rule DoppelPaymer
{
    meta:
        author = "kevoreilly"
        description = "DoppelPaymer Payload"
        cape_type = "DoppelPaymer Payload"

    strings:
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $cmd_string = "Setup run\n" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}

"""

LEN_BLOB_KEY = 40


def convert_char(c):
    if c in (string.letters + string.digits + string.punctuation + " \t\r\n"):
        return c
    else:
        return "\\x%02x" % ord(c)


def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "DoppelPaymer":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses


def extract_rdata(pe):
    for section in pe.sections:
        if ".rdata" in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None


class DoppelPaymer(Parser):

    DESCRIPTION = "DoppelPaymer configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)

        blobs = filter(None, [x.strip(b"\x00\x00\x00\x00") for x in extract_rdata(pe).split(b"\x00\x00\x00\x00")])
        for blob in blobs:
            if len(blob) < LEN_BLOB_KEY:
                continue
            raw = decrypt_rc4(blob[:LEN_BLOB_KEY][::-1], blob[LEN_BLOB_KEY:])
            if not raw:
                continue
            for item in raw.split(b"\x00"):
                data = "".join(convert_char(c) for c in item)
                if len(data) == 406:
                    self.reporter.add_metadata("other", {"RSA public key": data})
                elif len(data) > 1 and "\\x" not in data:
                    self.reporter.add_metadata("other", {"strings": data})
        return
