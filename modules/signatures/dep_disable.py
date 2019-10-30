# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

ProcessExecuteFlags = 34

class DEPDisable(Signature):
    name = "dep_disable"
    description = "A process disabled DEP at runtime"
    severity = 3
    categories = ["exploit"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtSetInformationProcess"])

    def on_call(self, call, process):
        infoclass = self.get_argument(call, "ProcessInformationClass")

        if infoclass is not None:
            infoclass = int(infoclass)
        # ProcessDEPPolicy
        if call["return"] == 0 and infoclass == ProcessExecuteFlags:
            processinfo = self.get_raw_argument(call, "ProcessInformation")
            if processinfo == 0:
                self.data.append({"process" : process["process_name"] + ":" + str(process["process_id"])})

    def on_complete(self):
         if self.data:
             return True
         return False
