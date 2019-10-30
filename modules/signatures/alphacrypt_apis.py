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

class Alphacrypt_APIs(Signature):
    name = "alphacrypt_behavior"
    description = "Exhibits behavior characteristic of Alphacrypt/Teslacrypt ransomware"
    weight = 3
    severity = 3
    categories = ["ransomware"]
    families = ["alphacrypt", "teslacrypt"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    ttps = ["T1486"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.extcount = 0
        self.c2s = set()
        self.uristruct = False
        self.urivars = ["sub", "addr", "size", "version", "os", "id", "inst_id"]
        self.pat = r"(?:https?:\/\/)?(?:[\da-z\.-]+)\.(?:[0-9a-z\.]{2,6})" \
                   r"(?:\d{1,5})?(?:[\/\w\.-]*)\/?"

    filter_apinames = set(["CryptDecrypt"])

    def on_call(self, call, process):
        if call["api"] == "CryptDecrypt":
            buf = self.get_argument(call, "Buffer")
            if buf:
                if self.uristruct and re.match(self.pat, buf):
                    self.c2s.add(buf.replace("\\x00", ""))
                # Indicator to be used later
                if buf.startswith(".") and len(buf) < 64:
                    self.extcount += 1
                # Parse for c2 structure
                else:
                    buf = buf.lower()
                    if all(s in buf for s in self.urivars):
                        self.uristruct = True


    def on_complete(self):
        ret = False
        # Observed with some samples, appears to be customizable though
        mutex_iocs = [
            "^78456214324124$",
        ]

        for ioc in mutex_iocs:
            if self.check_mutex(pattern=ioc, regex=True):
                ret = True

        if self.uristruct or self.extcount > 150:
            ret = True

        if ret:
            if self.c2s:
                for c2 in self.c2s:
                    self.data.append({"C2": c2})
            return True

        return False
