# CAPE - Config And Payload Extraction
# Copyright(C) 2018 redsand (redsand@redsand.net)
#
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class anomalous_deletefile(Signature):
    name = "anomalous_deletefile"
    description = "Anomalous file deletion behavior detected (10+)"
    severity = 2
    categories = ["malware"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True
    ttps = ["T1485"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1485"]
    mbcs += ["OC0001", "C0047"]  # micro-behaviour

    filter_apinames = set(["NtDeleteFile", "DeleteFileA", "DeleteFileW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.loadctr = 0
        self.list = []
        self.safelistprocs = [
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "acrord32.exe",
        ]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.safelistprocs:
            return

        if call["api"] == "NtDeleteFile" or call["api"] == "DeleteFileA" or call["api"] == "DeleteFileW":
            self.loadctr += 1
            self.data.append({"file": "%s" % (self.get_argument(call, "FileName"))})
            if self.pid:
                self.mark_call()

    def on_complete(self):
        if self.loadctr > 10:
            return True
