# Copyright (C) 2020 ditekshen
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


class GuLoaderAPIs(Signature):
    name = "guloader_apis"
    description = "Exhibits behavior characteristics of GuLoader"
    severity = 3
    categories = ["downloader", "injection"]
    families = ["GuLoader", "CloudEye"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(
        ["NtCreateFile", "RegOpenKeyExA", "SetWindowsHookExA", "SetWindowsHookExW", "InternetOpenA", "InternetOpenUrlA"]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.regpattern = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VBA\Monitors"
        self.filepatterns = [
            "^[A-Z]:\\\\ProgramData\\\\qemu-ga\\\\qga.state$",
            "^[A-Z]:\\\\Program\sFiles(\s\(x86\))?\\\\Qemu-ga\\\\qemu-ga.exe$",
            "^[A-Z]:\\\\Program\sFiles(\s\(x86\))?\\\\qga\\\\qga.exe$",
        ]
        self.uapattern = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        self.useragent = str()
        self.regmatch = False
        self.filematch = False
        self.hookmatch = False

    def on_call(self, call, process):
        if call["api"] == "NtCreateFile":
            desiredaccess = int(self.get_argument(call, "DesiredAccess"), 16)
            if desiredaccess and desiredaccess & 0x80100080:
                filename = self.get_argument(call, "FileName")
                for pat in self.filepatterns:
                    if filename and re.match(pat, filename, re.IGNORECASE):
                        self.filematch = True
                        if self.pid:
                            self.mark_call()

        if call["api"] == "RegOpenKeyExA":
            fullname = self.get_argument(call, "FullName")
            if fullname and fullname == self.regpattern:
                self.regmatch = True
                if self.pid:
                    self.mark_call()

        if call["api"] == "InternetOpenA" and self.filematch:
            self.useragent = self.get_argument(call, "Agent")
            if self.pid:
                self.mark_call()

        if call["api"] == "InternetOpenUrlA" and self.useragent == self.uapattern:
            url = self.get_argument(call, "URL")
            if url:
                self.data.append({"url": url})
                if self.pid:
                    self.mark_call()

        if call["api"] == "SetWindowsHookExA" or call["api"] == "SetWindowsHookExW":
            hookid = int(self.get_argument(call, "HookIdentifier"))
            praddr = self.get_argument(call, "ProcedureAddress")
            if hookid and hookid == 4294967295 and praddr and praddr == "0x729a1e09":
                self.hookmatch = True
                self.ttps += ["T1055"]  # MITRE v6,7,8
                self.mbcs += ["E1055", "E1055.m01"]
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.regmatch and self.filematch and self.hookmatch:
            return True

        return False
