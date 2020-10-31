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

from mwcp.parser import Parser
import struct
import pefile
import yara
from Crypto.Cipher import ARC4

yara_rule = """
rule IcedIDStage2
{
    meta:
        author = "kevoreilly"
        description = "IcedID Stage2 Payload"
        cape_type = "IcedID Stage2 Payload"
    strings:
        $crypt1 = {8A 04 ?? D1 C? F7 D? D1 C? 81 E? 20 01 00 00 D1 C? F7 D? 81 E? 01 91 00 00 32 C? 88}
        $crypt2 = {8B 44 24 04 D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 C3}
        $crypt3 = {41 00 8B C8 C1 E1 08 0F B6 C4 66 33 C8 66 89 4? 24 A1 ?? ?? 41 00 89 4? 20 A0 ?? ?? 41 00 D0 E8 32 4? 32}
        $download1 = {8D 44 24 40 50 8D 84 24 44 03 00 00 68 04 21 40 00 50 FF D5 8D 84 24 4C 01 00 00 C7 44 24 28 01 00 00 00 89 44 24 1C 8D 4C 24 1C 8D 84 24 4C 03 00 00 83 C4 0C 89 44 24 14 8B D3 B8 BB 01 00 00 66 89 44 24 18 57}
        $download2 = {8B 75 ?? 8D 4D ?? 8B 7D ?? 8B D6 57 89 1E 89 1F E8 [4] 59 3D C8 00 00 00 75 05 33 C0 40 EB}
        $major_ver = {0F B6 05 ?? ?? ?? ?? 6A ?? 6A 72 FF 75 0C 6A 70 50 FF 35 ?? ?? ?? ?? 8D 45 80 FF 35 ?? ?? ?? ?? 6A 63 FF 75 08 6A 67 50 FF 75 10 FF 15 ?? ?? ?? ?? 83 C4 38 8B E5 5D C3}
        $stage_2_request_binary = "?id=%0.2X%0.8X%0.8X%s"
        $stage_2_request_img = ".png"

    condition:
        any of ($crypt*, $download*, $major_ver) and all of ($stage_2_*)

}
"""
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
