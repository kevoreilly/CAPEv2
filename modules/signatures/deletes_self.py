# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com)
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

class DeletesSelf(Signature):
    name = "deletes_self"
    description = "Deletes its original binary from disk"
    severity = 3
    categories = ["persistence"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # get the path of the initial monitored executable
        self.initialpath = None
        initialproc = self.get_initial_process()
        if initialproc:
            self.initialpath = initialproc["module_path"].lower()

    filter_apinames = set(["NtDeleteFile","DeleteFileA", "DeleteFileW", "MoveFileWithProgressW","MoveFileWithProgressTransactedW"])

    def on_call(self, call, process):
        if not call["status"]:
            return None

        if call["api"] != "MoveFileWithProgressW" and call["api"] != "MoveFileWithProgressTransactedW":
            filename = self.get_argument(call, "FileName").lower()
            if filename == self.initialpath:
                return True
        else:
            filename = self.get_argument(call, "ExistingFileName").lower()
            # here we treat any move from the original binary's location as a deletion, including
            # cases where the original containing directory has been moved
            if filename == self.initialpath or (len(filename) > 1 and ((filename[-1] == '\\' and self.initialpath.startswith(filename)) or self.initialpath.startswith(filename + "\\"))):
                return True
