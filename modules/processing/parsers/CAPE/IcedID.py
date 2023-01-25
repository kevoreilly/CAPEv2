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
#
# Updates to handle stage 1 Based on initial work referenced here and modified to work with python3
# https://sysopfb.github.io/malware,/icedid/2020/04/28/IcedIDs-updated-photoloader.html
# https://gist.github.com/sysopfb/93eb0090ef47c08e4e516cb045b48b96
# https://www.group-ib.com/blog/icedid

import logging
import os
import struct

import pefile
import yara
from Cryptodome.Cipher import ARC4

from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "IcedID.yar")
with open(yara_path, "r") as yara_rule:
    yara_rules = yara.compile(source=yara_rule.read())

log = logging.getLogger(__name__)

DESCRIPTION = "IcedID Stage 2 configuration parser."
AUTHOR = "kevoreilly,threathive,sysopfb"


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        print(e)


def extract_config(filebuf):
    yara_hit = yara_scan(filebuf)

    for hit in yara_hit:
        if hit.rule == "IcedID":  # can be either a dll or a exe
            enc_data = None
            try:
                pe = pefile.PE(data=filebuf, fast_load=True)
                for section in pe.sections:
                    if section.Name == b".data\x00\x00\x00":
                        enc_data = section.get_data()
                        key = enc_data[:8]
                        enc_config = enc_data[8:592]
                        decrypted_data = ARC4.new(key).decrypt(enc_config)
                        config = list(filter(None, decrypted_data.split(b"\x00")))
                        return {
                            "family": "IcedID",
                            "version": str(struct.unpack("I", decrypted_data[4:8])[0]),
                            "paths": [{"path": config[1].decode(), "usage": "other"}],
                            "http": [{"uri": controller[1:].decode()} for controller in config[2:]],
                            "other": {
                                "Bot ID": str(struct.unpack("I", decrypted_data[:4])[0]),
                            },
                        }
            except Exception as e:
                log.error("Error: %s", e)

            return {}


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
