# Copyright (C) 2018 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
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

import os
import struct
import socket
import pefile
import yara
from mwcp.parser import Parser
from lib.cuckoo.common.constants import CUCKOO_ROOT

yara_path = os.path.join(CUCKOO_ROOT, "data", "yara", "CAPE", "DridexLoader.yar")
rule_source = open(yara_path, "r").read()

MAX_IP_STRING_SIZE = 16       # aaa.bbb.ccc.ddd\0

class DridexLoader(Parser):

    DESCRIPTION = 'DridexDropper configuration parser.'
    AUTHOR = 'kevoreilly'

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=filebuf, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        delta = 0

        yara_rules = yara.compile(source=rule_source)
        matches = yara_rules.match(data=filebuf)
        if not matches:
            return

        line, c2va_offset = False, False
        for match in matches:
            if match.rule != 'DridexLoader':
                continue

            for item in match.strings:
                if item[1] in ('$c2parse_4', '$c2parse_3', '$c2parse_2', '$c2parse_1'):
                    c2va_offset = int(item[0])
                    line = item[1]
                    break

        if line == '$c2parse_4':
            c2_rva = struct.unpack('i', filebuf[c2va_offset+6:c2va_offset+10])[0] - image_base + 1
        elif line == '$c2parse_3':
            c2_rva = struct.unpack('i', filebuf[c2va_offset+60:c2va_offset+64])[0] - image_base
            delta = 2
        elif line == '$c2parse_2':
            c2_rva = struct.unpack('i', filebuf[c2va_offset+47:c2va_offset+51])[0] - image_base
        elif line == '$c2parse_1':
            c2_rva = struct.unpack('i', filebuf[c2va_offset+27:c2va_offset+31])[0] - image_base
            delta = 2
        else:
            return

        c2_offset = pe.get_offset_from_rva(c2_rva)

        for i in range(0, 4):
            ip = struct.unpack('>I', filebuf[c2_offset:c2_offset+4])[0]
            c2_address = socket.inet_ntoa(struct.pack('!L', ip))
            port = str(struct.unpack('H', filebuf[c2_offset+4:c2_offset+6])[0])

            if c2_address and port:
                self.reporter.add_metadata('address', c2_address+':' + port)

            c2_offset += (6 + delta)

        return
