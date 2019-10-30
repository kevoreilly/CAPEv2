# Copyright (C) 2017 KillerInstinct
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

class iSpyKeylogger_APIs(Signature):
    name = "ispy_behavior"
    description = "Exhibits behavior characteristic of iSpy Keylogger"
    weight = 3
    severity = 3
    categories = ["keylogger"]
    families = ["ispy"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badpid = 0
        self.crypted_count = 0
        self.crypt_mutex = False
        self.found = False
        self.last_mutex = ""
        self.last_api = ""
        self.c2ip = ""
        self.c2domain = ""
        self.c2user = ""

    filter_apinames = set(["CryptHashData", "NtCreateMutant", "getaddrinfo",
                           "WSAConnect", "send"])

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            buf = self.get_argument(call, "Buffer")
            if buf == self.last_mutex:
                self.badpid = process["process_id"]
                return None

            if process["process_id"] == self.badpid:
                if len(buf) in [50, 56]:
                    self.crypted_count += 1

            if self.crypted_count == 50:
                self.found = True

        elif call["api"] == "NtCreateMutant":
            self.last_mutex = self.get_argument(call, "MutexName")

        elif call["api"] == "getaddrinfo":
            if process["process_id"] == self.badpid:
                dn = self.get_argument(call, "NodeName")
                if dn:
                    self.c2domain = dn

        elif call["api"] == "WSAConnect":
            if process["process_id"] == self.badpid:
                if self.last_api == "getaddrinfo" or self.found:
                    ip = self.get_argument(call, "ip")
                    port = self.get_argument(call, "port")
                    if ip:
                        self.c2ip = ip
                    # Don't add domains to self.data here as iSpy will make a request to
                    # checkip.dyndns.org. We'll add this later when we detect a POST verb
                    if port != "80":
                        tmp = {"C2": self.c2ip}
                        if tmp not in self.data and self.c2ip:
                            self.data.append(tmp)
                        if self.c2domain:
                            tmp = {"C2": self.c2domain}
                            if tmp not in self.data and self.c2domain:
                                self.data.append(tmp)

        elif call["api"] == "send":
            if process["process_id"] == self.badpid and self.last_api == "WSAConnect":
                addc2 = False
                buf = self.get_argument(call, "buffer")
                # Handle FTP C2
                if buf.startswith("USER "):
                    addc2 = True
                    self.c2user = buf.split()[1]
                # Handle HTTP C2
                elif buf.startswith("POST "):
                    addc2 = True
                    self.c2domain += buf.split()[1]
                # TODO: SMTP C2
                if addc2:
                    tmp = {"C2": self.c2ip}
                    if tmp not in self.data:
                        self.data.append(tmp)
                    tmp = {"C2": self.c2domain}
                    if tmp not in self.data:
                        self.data.append(tmp)
                    if self.c2user:
                        self.data.append({"User": self.c2user})

        self.last_api = call["api"]

    def on_complete(self):
        if self.found:
            return True

        return False
