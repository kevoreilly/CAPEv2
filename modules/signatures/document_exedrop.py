# Copyright (C) 2021 Kevin Ross
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


class DocScriptEXEDrop(Signature):
    name = "document_script_exe_drop"
    description = "A document or script wrote an executable file to disk"
    severity = 3
    categories = ["dropper", "downloader"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1059"]
    evented = True

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.dropped = []
        self.pnames = [
            "acrord32.exe",
            "acrord64.exe",
            "cscript.exe",
            "excel.exe",
            "jscript.exe",
            "mshta.exe",
            "mspub.exe",
            "powerpnt.exe",
            "winword.exe",
            "wordview.exe",
            "wscript.exe",
            "powershell.exe",
        ]

    def on_call(self, call, process):
        pname = process["process_name"]
        if pname.lower() in self.pnames:
            buf = self.get_argument(call, "Buffer")
            handle = self.get_argument(call, "HandleName")
            if buf.startswith("MZ") or handle.endswith((".exe", ".dll", ".sys", ".msi")):
                self.ret = True
                if handle not in self.dropped:
                    self.dropped.append(handle)
                    if self.pid:
                        self.mark_call()
                    self.data.append({"file": "%s dropped file %s" % (pname, handle)})

    def on_complete(self):
        return self.ret
