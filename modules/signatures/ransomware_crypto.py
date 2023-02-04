# Copyright (C) 2020 Kevin Ross
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


class MassDataEncryption(Signature):
    name = "mass_data_encryption"
    description = (
        "Performs a large number of encryption calls using the same key possibly indicative of ransomware file encryption behavior"
    )
    severity = 3
    confidence = 10
    categories = ["encryption", "ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]
    mbcs += ["OC0005", "C0027", "C0028"]  # micro-behaviour

    filter_apinames = set(["CryptEncrypt"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptkeys = {}
        self.procwhitelist = [
            "acrobat.exe",
            "acrord32.exe",
            "chrome.exe",
            "excel.exe",
            "firefox.exe",
            "hwp.exe",
            "iexplore.exe",
            "outlook.exe",
            "powerpnt.exe",
            "winword.exe",
        ]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname not in self.procwhitelist:
            cryptkey = self.get_argument(call, "CryptKey")
            if cryptkey not in self.cryptkeys:
                self.cryptkeys[cryptkey] = 1
            else:
                self.cryptkeys[cryptkey] += 1

    def on_complete(self):
        ret = False
        for key, value in self.cryptkeys.items():
            if value >= 200:
                ret = True
                self.data.append({"encryption": "The crypto key %s was used %s times to encrypt data" % (key, value)})

        return ret
