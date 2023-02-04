# Copyright (C) 2020 bartblaze
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


# Detects suspicious behaviour where malware stores or writes data/files to the recycler
class Accesses_RecycleBin(Signature):
    name = "accesses_recyclebin"
    description = "Manipulates data from or to the Recycle Bin"
    severity = 2
    categories = ["evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1074"]  # MITRE v6,7,8

    filter_apinames = set(["NtCreateFile", "NtOpenFile", "NtReadFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.filepattern = "^[A-Z]:\\\\\$Recycle.Bin\\\\*"
        self.filematch = False
        self.filenames = list()

    def on_call(self, call, process):
        if call["api"] == "NtCreateFile":
            desiredaccess = int(self.get_argument(call, "DesiredAccess"), 16)
            if desiredaccess and (desiredaccess & 0x80100080 or desiredaccess & 0x00110081):
                filename = self.get_argument(call, "FileName")
                if filename and re.match(self.filepattern, filename, re.IGNORECASE):
                    self.filematch = True
                    self.filenames.append(filename)
                    if self.pid:
                        self.mark_call()

        if call["api"] == "NtOpenFile":
            desiredaccess = int(self.get_argument(call, "DesiredAccess"), 16)
            if desiredaccess and desiredaccess & 0x00020080:
                filename = self.get_argument(call, "FileName")
                if filename and re.match(self.filepattern, filename, re.IGNORECASE):
                    self.filematch = True
                    self.filenames.append(filename)
                    if self.pid:
                        self.mark_call()

        if call["api"] == "NtReadFile":
            filename = self.get_argument(call, "FileName")
            if filename and re.match(self.filepattern, filename, re.IGNORECASE):
                self.filematch = True
                self.filenames.append(filename)
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.filematch and self.filenames:
            for file in self.filenames:
                self.data.append({"file": file})

        return self.filematch
