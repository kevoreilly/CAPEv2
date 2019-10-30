# Copyright (C) 2016 Kevin Ross.
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

class DecoyDocument(Signature):
    name = "decoy_document"
    description = "A potential decoy document was displayed to the user"
    severity = 3
    confidence = 10
    categories = ["exploit", "stealth", "decoy"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.decoys = []
        self.office_proc_list =["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","acrord64.exe"]
        self.initialpath = None
        initialproc = self.get_initial_process()
        if initialproc:
            self.initialpath = initialproc["module_path"].lower()

    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.office_proc_list:
            docpath = process["environ"]["CommandLine"].lower()
            if self.initialpath not in docpath and docpath not in self.decoys:
                self.decoys.append(docpath)

    def on_complete(self):
        if self.results["info"]["package"] in ["exe", "bin", "msi", "dll"]:
            self.data.append({"disguised_executable" : "The submitted file was an executable indicative of an attempt to get a user to run executable content disguised as a document" })
            self.confidence = 80

        if len(self.decoys) > 0:
            for decoy in self.decoys:
                self.data.append({"Decoy Document" : "%s" % (decoy)})
            return True

        return False
