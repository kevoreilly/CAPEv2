# Copyright (C) 2015-2016 KillerInstinct
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
try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.signature_utils import DridexDecode_v1

class Dridex_APIs(Signature):
    name = "dridex_behavior"
    description = "Exhibits behavior characteristic of Dridex malware"
    weight = 3
    severity = 3
    categories = ["banker", "trojan"]
    families = ["dridex"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compname = ""
        self.username = ""
        self.is_xp = False
        self.crypted = []
        # Set to false if you don't want to extract c2 IPs
        self.extract = True
        self.sockmon = dict()
        self.payloadip = dict()
        self.decompMZ = False
        self.ip_check = str()
        self.port_check = str()
        self.post_check = False
        self.ret = False

    filter_apinames = set(["RegQueryValueExA", "CryptHashData", "connect", "send", "recv",
                           "RtlDecompressBuffer", "InternetConnectW", "HttpOpenRequestW",
                           "InternetCrackUrlA"])

    def on_call(self, call, process):
        if call["api"] == "RegQueryValueExA":
            # There are many more ways to get the computer name, this is the
            # pattern observed with all Dridex varients 08/14 - 03/15 so far.
            testkey = self.get_argument(call, "FullName").lower()
            if testkey == "hkey_local_machine\\system\\controlset001\\control\\computername\\computername\\computername":
                buf = self.get_argument(call, "Data")
                if buf:
                    self.compname = buf.lower()
            if testkey == "hkey_current_user\\volatile environment\\username":
                if call["status"]:
                    buf = self.get_argument(call, "Data")
                    if buf:
                        self.username = buf.lower()
                else:
                    self.is_xp = True

        elif call["api"] == "CryptHashData":
            self.crypted.append(self.get_argument(call, "Buffer").lower())

        elif call["api"] == "connect":
            if not self.extract:
                return None

            socknum = str(self.get_argument(call, "socket"))
            if socknum and socknum not in self.sockmon.keys():
                self.sockmon[socknum] = ""

            lastip = self.get_argument(call, "ip")
            self.sockmon[socknum] = lastip

        elif call["api"] == "send":
            if not self.extract:
                return None

            socknum = str(self.get_argument(call, "socket"))
            if socknum and socknum in self.sockmon.keys():
                buf = self.get_argument(call, "buffer")
                # POST is a stable indicator observed so far
                if buf and buf[:4] == "POST":
                    self.payloadip["send"] = self.sockmon[socknum]

        elif call["api"] == "recv":
            if not self.extract:
                return None

            socknum = str(self.get_argument(call, "socket"))
            if socknum and socknum in self.sockmon.keys():
                buf = self.get_argument(call, "buffer")
                if buf:
                    clen = re.search(r"Content-Length:\s([^\s]+)", buf)
                    if clen:
                        length = int(clen.group(1))
                        if length > 100000:
                            if "send" in self.payloadip and self.sockmon[socknum] == self.payloadip["send"]:
                                # Just a sanity check to make sure the IP hasn't changed
                                # since this is a primitive send/recv monitor
                                self.payloadip["recv"] = self.sockmon[socknum]

        elif call["api"] == "RtlDecompressBuffer":
            buf = self.get_argument(call, "UncompressedBuffer")
            if buf.startswith("MZ"):
                self.decompMZ = True

        elif call["api"] == "InternetConnectW":
            if self.decompMZ:
                ip = self.get_argument(call, "ServerName")
                if not any(char.isalpha() for char in ip):
                    self.ip_check = ip
                    self.port_check = str(self.get_argument(call, "ServerPort"))

        elif call["api"] == "HttpOpenRequestW":
            if self.ip_check and self.port_check:
                if self.get_argument(call, "Verb") == "POST":
                    self.post_check = True

        elif call["api"] == "InternetCrackUrlA":
            if self.post_check:
                buf = self.get_argument(call, "Url")
                if buf.lower().startswith("https") and self.port_check != "443":
                    if buf.lower().split("/")[-1] == self.ip_check:
                        self.ret = True

        return None


    def on_complete(self):
        if self.compname and (self.username or self.is_xp) and self.crypted:
            buf = self.compname + self.username
            for item in self.crypted:
                if buf in item:
                    self.ret = True

        pattern = r".*\\CurrentVersion\\Explorer\\CLSID\\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\\ShellFolder\\[0-9A-Fa-f]{8,24}"
        if self.check_write_key(pattern=pattern, regex=True):
            self.ret = True

        if self.extract and self.ret and self.payloadip and "recv" in self.payloadip:
            if "suricata" in self.results and "files" in self.results["suricata"]:
                for sfile in self.results["suricata"]["files"]:
                    if int(sfile["size"]) > 100000 and sfile["srcip"] == self.payloadip["recv"]:
                        if "file_info" in sfile.keys():
                                payload = sfile["file_info"]["path"]
                                decoder = DridexDecode_v1()
                                decoded = decoder.run(payload)
                                if decoded:
                                    # We got the IPs :)
                                    for ip in decoded:
                                        self.data.append({"ioc": ip})
                                break

        return self.ret
