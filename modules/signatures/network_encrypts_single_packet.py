# Copyright (C) 2019 ditekshen
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

class EncryptsSingleHTTPPacket(Signature):
    name = "encrypt_single_http_packet"
    description = "Encrypts a single HTTP packet"
    severity = 2
    categories = ["network", "encryption"]
    families = [""]
    authors = ["ditekshen"]
    minimum = "0.5"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.httpverbs = [
            "GET",
            "POST",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for verb in self.httpverbs:
                if buff.startswith(verb):
                    self.match = True
                    self.data.append({"http_request": buff})

    def on_complete(self):
        return self.match
