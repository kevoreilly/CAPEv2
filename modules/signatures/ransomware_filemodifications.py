# Copyright (C) 2016 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re

class RansomwareFileModifications(Signature):
    name = "ransomware_file_modifications"
    description = "Exhibits possible ransomware file modification behavior"
    severity = 3
    confidence = 50
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1486"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.movefilecount = 0
        self.appendcount = 0
        self.appendemailcount = 0
        self.newextensions = []

    filter_apinames = set(["MoveFileWithProgressW","MoveFileWithProgressTransactedW"])

    def on_call(self, call, process):
        if not call["status"]:
            return None
        origfile = self.get_argument(call, "ExistingFileName")
        newfile = self.get_argument(call, "NewFileName")
        self.movefilecount += 1
        if origfile != newfile and "@" not in newfile:
            origextextract = re.search("^.*(\.[a-zA-Z0-9_\-]{1,}$)", origfile)
            if not origextextract:
                return None
            origextension = origextextract.group(1)
            newextextract = re.search("^.*(\.[a-zA-Z0-9_\-]{1,}$)", newfile)
            if not newextextract:
                return None
            newextension = newextextract.group(1)
            if newextension != ".tmp":
                if origextension != newextension:
                    self.appendcount += 1
                    if self.newextensions.count(newextension) == 0:
                        self.newextensions.append(newextension)
        if origfile != newfile and "@" in newfile:
            self.appendemailcount += 1

    def on_complete(self):
        ret = False

        deletedfiles = self.results["behavior"]["summary"]["delete_files"]
        deletedcount = 0
        for deletedfile in deletedfiles:
            if "\\temp\\" not in deletedfile.lower() and "\\temporary internet files\\" not in deletedfile.lower() and "\\cache" not in deletedfile.lower() and not deletedfile.lower().endswith(".tmp"):
                deletedcount += 1
        if deletedcount > 100:
            self.data.append({"mass file_deletion" : "Appears to have deleted %s files indicative of ransomware or wiper malware deleting files to prevent recovery" % (deletedcount)})
            ret = True

        if self.movefilecount > 60:
            self.data.append({"file_modifications" : "Performs %s file moves indicative of a potential file encryption process" % (self.movefilecount)})
            ret = True

        if self.appendemailcount > 60:
            self.data.append({"appends_email" : "Appears to have appended an email address onto %s files. This is used by ransomware which requires the user to email the attacker for payment/recovery actions" % (self.appendemailcount)})

        if "dropped" in self.results:
            droppedunknowncount = 0
            for dropped in self.results["dropped"]:
                mimetype = dropped["type"]
                filename = dropped["name"]
                if mimetype == "data" and ".tmp" not in filename and "CryptnetUrlCache" not in filename:
                    droppedunknowncount += 1
            if droppedunknowncount > 50 and self.results["info"]["package"] != "pdf":
                self.data.append({"drops_unknown_mimetypes" : "Drops %s unknown file mime types which may be indicative of encrypted files being written back to disk" % (droppedunknowncount)})
                ret = True

        # Note: Always make sure this check is at bottom so that appended file extensions are underneath behavior alerts
        if self.appendcount > 40:
            # This check is to prevent any cases where there is a large number of unique appended extensions resulting in an overly large list
            newcount = len(self.newextensions)
            if newcount > 15:
                self.data.append({"appends_new_extension" : "Appended %s unique file extensions to multiple modified files" % (newcount)})
            if newcount < 16:
                self.data.append({"appends_new_extension" : "Appends a new file extension to multiple modified files" })
                for newextension in self.newextensions:
                    self.data.append({"new_appended_file_extension" : newextension})
            ret = True

        return ret
