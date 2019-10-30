# Copyright (C) 2015 KillerInstinct
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

class Shifu_APIs(Signature):
    name = "shifu_behavior"
    description = "Exhibits behavior characteristics of Shifu malware."
    severity = 3
    weight = 3
    categories = ["banking", "trojan"]
    families = ["shifu"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["NtQuerySystemInformation", "CryptHashData",
                           "NtQueryValueKey", "CryptDecodeObjectEx"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.malscore = int()
        self.certBuffer = str()
        self.countCertificates = int()
        self.lastcall = str()

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            if self.lastcall == "NtQuerySystemInformation":
                buf = self.get_argument(call, "Buffer").lower()
                if buf and "windows_" in buf:
                    self.malscore += 1

        if call["api"] == "NtQueryValueKey":
            if self.get_argument(call, "ValueName") == "Blob":
                key = self.get_argument(call, "FullName")
                if "\\SOFTWARE\\Microsoft\\SystemCertificates\\" in key:
                    self.certBuffer = self.get_argument(call, "Information")

        if call["api"] == "CryptDecodeObjectEx":
            if self.lastcall == "NtQueryValueKey":
                buf = self.get_argument(call, "Encoded")[0:64]
                if buf in self.certBuffer:
                    self.countCertificates += 1

        self.lastcall = call["api"]

    def on_complete(self):
        file_iocs = [
            "^[A-Za-z]:\\\\sample\\\\pos.exe$",
            "^[A-Za-z]:\\\\ProgramData\\\\ELBA5\\\\ELBA_data$",
            "^[A-Za-z]:\\\\analysis$",
            "^[A-Za-z]:\\\\tmp\\\\debug.txt$",
        ]
        for ioc in file_iocs:
            if self.check_file(pattern=ioc, regex=True):
                self.malscore += 1

        mutex_iocs = [
            "^(Global|Local)\\\\\{[0-9a-f]{20}\}$",
            "^[0-9a-f]{16}$",
        ]
        for ioc in mutex_iocs:
            if self.check_mutex(pattern=ioc, regex=True):
                self.malscore += 1

        if self.countCertificates > 20:
            self.malscore += 4

        if self.malscore >= 10:
            return True

        return False
