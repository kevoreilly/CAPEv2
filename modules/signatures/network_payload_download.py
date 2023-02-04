# Copyright (C) 2016 Kevin Ross. Also uses code from Will Metcalf
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


class NetworkDocumentFile(Signature):
    name = "network_document_file"
    description = "A document or script file initiated network communications indicative of a potential exploit or payload download"
    severity = 3
    categories = ["exploit", "downloader"]
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "Will Metcalf", "@CybercentreCanada"]
    minimum = "1.2"
    ttps = ["T1071"]
    evented = True

    filter_apinames = set(
        [
            "InternetCrackUrlW",
            "InternetCrackUrlA",
            "URLDownloadToFileW",
            "URLDownloadToCacheFileW",
            "HttpOpenRequestW",
            "WSASend",
            "send",
        ]
    )
    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.proc_list = [
            "wordview.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "acrord32.exe",
            "acrord64.exe",
            "wscript.exe",
            "mspub.exe",
            "powershell.exe",
        ]

    def on_call(self, _, process):
        pname = process["process_name"].lower()
        if pname in self.proc_list:
            if self.pid:
                self.mark_call()
            return True


class NetworkEXE(Signature):
    name = "network_downloader_exe"
    description = "An executable file was downloaded"
    severity = 2
    categories = ["exploit", "downloader"]
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "Will Metcalf", "@CybercentreCanada"]
    minimum = "1.2"
    ttps = ["T1129"]
    evented = True

    filter_apinames = set(["recv", "InternetReadFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.high_risk_proc = [
            "wordview.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "acrord32.exe",
            "acrord64.exe",
            "wscript.exe",
            "java.exe",
            "javaw.exe",
            "powershell.exe",
        ]

    def on_call(self, call, process):
        if call["api"] == "recv":
            buf = self.get_argument(call, "buffer")
        elif call["api"] == "InternetReadFile":
            buf = self.get_argument(call, "Buffer")
        else:
            return
        pname = process["process_name"].lower()
        if buf and "MZ" in buf and "This program" in buf:
            if pname in self.high_risk_proc:
                self.severity = 3
            if self.pid:
                self.mark_call()
            return True
