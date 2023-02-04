# Copyright (C) 2016 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re


class RansomwareMessage(Signature):
    name = "ransomware_message"
    description = "Writes a potential ransom message to disk"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross", "bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]
    mbcs += ["OC0001", "C0016"]  # micro-behaviour

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.indicators = [
            "your files",
            "your data",
            "your documents",
            "restore files",
            "restore data",
            "restore the files",
            "restore the data",
            "recover files",
            "recover data" "recover the files",
            "recover the data",
            "has been locked",
            "pay fine",
            "pay a fine",
            "pay the fine",
            "decrypt",
            "encrypt",
            "recover files",
            "recover data",
            "recover them",
            "recover your",
            "recover personal",
            "bitcoin",
            "secret server",
            "secret internet server",
            "install tor",
            "download tor",
            "tor browser",
            "tor gateway",
            "tor-browser",
            "tor-gateway",
            "torbrowser",
            "torgateway",
            "torproject.org",
            "ransom",
            "bootkit",
            "rootkit",
            "payment",
            "victim",
            "AES128",
            "AES256",
            "AES 128",
            "AES 256",
            "AES-128",
            "AES-256",
            "RSA1024",
            "RSA2048",
            "RSA4096",
            "RSA 1024",
            "RSA 2048",
            "RSA 4096",
            "RSA-1024",
            "RSA-2048",
            "RSA-4096",
            "private key",
            "personal key",
            "your code",
            "private code",
            "personal code",
            "enter code",
            "your key",
            "unique key",
            "your database",
            "encrypted",
            "bit coin",
            "BTC",
            "ethereum",
            "what happened",
            "what happend",
            "decryptor",
            "decrypter",
            "personal ID",
            "unique ID",
            "encryption ID",
            "device ID",
            "HardwareID",
            "recover my",
            "wallet address",
            "localbitcoins",
            "Attention!",
            "restore the system",
            "restore system",
            "military grade encryption",
            "personal identifier",
            "personal identification code",
            "get back my",
            "get back your",
            "your network",
        ]
        self.patterns = "|".join(self.indicators)

    def on_call(self, call, process):
        buff = self.get_raw_argument(call, "Buffer").lower()
        filepath = self.get_raw_argument(call, "HandleName")
        if (
            filepath.lower() == "\\??\\physicaldrive0"
            or filepath.lower().startswith("\\device\\harddisk")
            or filepath.lower().endswith(".txt")
        ) and len(buff) >= 128:
            if len(set(re.findall(self.patterns, buff))) > 1:
                self.data.append({"ransom_note": "%s" % (filepath)})
                self.data.append({"begining_of_ransom_message": "%s" % (buff)})
                if self.pid:
                    self.mark_call()
                return True
