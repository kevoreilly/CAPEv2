# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
#
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

from lib.cuckoo.common.abstracts import Signature
import struct

class Chimera_APIs(Signature):
    name = "chimera_behavior"
    description = "Exhibits behavior characteristic of Chimera ransomware"
    weight = 3
    severity = 3
    categories = ["trojan"]
    families = ["chimera"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sysvolserial = self.get_environ_entry(self.get_initial_process(), "SystemVolumeSerialNumber")
        if self.sysvolserial:
            self.sysvolserial = int(self.sysvolserial.replace("-",""), 16)
            dword1 = (((0x19660d * self.sysvolserial) & 0xffffffff) + 0x3c6ef35f) & 0xffffffff
            dword2 = (((0x19660d * dword1) & 0xffffffff) + 0x3c6ef35f) & 0xffffffff
            word2 = dword2 & 0xffff
            serialnum = (((0x19660d * dword2) & 0xffffffff) + 0x3c6ef35f) & 0xffffffff
            word3 = serialnum & 0xffff
            buf = bytearray(8)
            for i in range(8):
                serialnum = (((0x19660d * serialnum) & 0xffffffff) + 0x3c6ef35f) & 0xffffffff
                buf[i] = serialnum & 0xff
            word4, dword5, word6 = struct.unpack("<HIH", str(buf))
            self.mutexmatch = "{{{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:08X}{5:04X}}}".format(dword1, word2, word3, word4, dword5, word6)

    filter_apinames = set(["NtCreateMutant"])

    def on_call(self, call, process):
        mutexname = self.get_argument(call, "MutexName")
        if mutexname == self.mutexmatch:
                return True
