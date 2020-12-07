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
#https://www.group-ib.com/blog/icedid

import os
import struct
import pefile
import yara
from Crypto.Cipher import ARC4
from mwcp.parser import Parser
from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "IcedIDStage2.yar")
yara_rule = open(yara_path, "r").read()

def yara_scan(raw_data):
    try:
        addresses = {}
        yara_rules = yara.compile(source=yara_rule)
        matches = yara_rules.match(data=raw_data)
        return matches
    except Exception as e:
        print(e)

class IcedIDStage2(Parser):

    DESCRIPTION = "IcedID Stage 2 configuration parser."
    AUTHOR = "kevoreilly,threathive,sysopfb"

    def run(self):
        filebuf = self.file_object.file_data
        yara_hit = yara_scan(filebuf)

        for hit in yara_hit:
            if hit.rule == "IcedIDStage2": #can be either a dll or a exe
                enc_data = None
                try:
                    pe = pefile.PE(data=filebuf, fast_load=False)
                    for section in pe.sections:
                        if section.Name == b'.data\x00\x00\x00':
                            enc_data = section.get_data()
                            key = enc_data[:8]
                            enc_config = enc_data[8:592]
                            decrypted_data = ARC4.new(key).decrypt(enc_config)
                            config = list(filter(None, decrypted_data.split(b"\x00") ))

                            self.reporter.add_metadata("other", {"Bot ID": str(struct.unpack("I", decrypted_data[:4])[0]) })
                            self.reporter.add_metadata("other", {"Minor Version": str(struct.unpack("I", decrypted_data[4:8])[0])})
                            self.reporter.add_metadata("other", {"Path": config[1] })
                            for controller in config[2:]:
                                self.reporter.add_metadata("address", controller[1:])

                except Exception as e:
                    self.logger.error("error:{}".format(e))
                    pass
