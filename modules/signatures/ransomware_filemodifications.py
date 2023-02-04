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
    description = "Exhibits possible ransomware or wiper file modification behavior"
    severity = 3
    confidence = 50
    categories = ["ransomware", "wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]

    filter_apinames = set(["MoveFileWithProgressW", "MoveFileWithProgressTransactedW", "NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.movefilecount = 0
        self.appendcount = 0
        self.appendemailcount = 0
        self.modifiedexistingcount = 0
        self.newextensions = []

    def on_call(self, call, process):
        if not call["status"]:
            return None
        if call["api"].startswith("MoveFileWithProgress"):
            origfile = self.get_argument(call, "ExistingFileName")
            newfile = self.get_argument(call, "NewFileName")
            if origfile.find("\\AppData\\Local\\Microsoft\\Windows\\Explorer\\iconcache_") and newfile.find(
                "\\AppData\\Local\\Microsoft\\Windows\\Explorer\\IconCacheToDelete\\"
            ):
                return None
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
                if self.pid and self.appendemailcount <= 10:
                    self.mark_call()

        if call["api"] == "NtCreateFile":
            existed = self.get_argument(call, "ExistedBefore")
            if existed == "yes":
                self.modifiedexistingcount += 1
                if self.pid and self.modifiedexistingcount <= 10:
                    self.mark_call()

    def on_complete(self):
        ret = False

        deletedfiles = self.results["behavior"]["summary"]["delete_files"]
        deletedcount = 0
        for deletedfile in deletedfiles:
            if (
                "\\temp\\" not in deletedfile.lower()
                and "\\temporary internet files\\" not in deletedfile.lower()
                and "\\cache" not in deletedfile.lower()
                and not deletedfile.lower().endswith(".tmp")
            ):
                deletedcount += 1
        if deletedcount > 60:
            if ":" in self.description:
                self.description += " mass_file_deletion"
            else:
                self.description += ": mass_file_deletion"
            self.mbcs += ["OC0001", "C0047"]  # micro-behaviour
            ret = True

        if self.movefilecount > 30:
            if ":" in self.description:
                self.description += " suspicious_file_moves"
            else:
                self.description += ": suspicious_file_moves"
            self.mbcs += ["OC0005", "C0027"]  # micro-behaviour
            ret = True

        if self.appendemailcount > 30:
            if ":" in self.description:
                self.description += " appends_email_to_filenames"
            else:
                self.description += ": appends_email_to_filenames"
            ret = True

        if self.modifiedexistingcount > 50:
            if ":" in self.description:
                self.description += " overwrites_existing_files"
            else:
                self.description += ": overwrites_existing_files"
            ret = True

        # This needs tweaked. No longer works due to dropped files limits in CAPE
        if "dropped" in self.results:
            droppedunknowncount = 0
            for dropped in self.results["dropped"]:
                mimetype = dropped["type"]
                filename = dropped["name"]
                if mimetype == "data" and ".tmp" not in filename and "CryptnetUrlCache" not in filename:
                    droppedunknowncount += 1
            if droppedunknowncount > 50 and self.results["info"]["package"] != "pdf":
                if ":" in self.description:
                    self.description += " mass_drops_unknown_filetypes"
                else:
                    self.description += ": mass_drops_unknown_filetypes"
                ret = True

        # Note: Always make sure this check is at bottom so that appended file extensions are underneath behavior alerts
        if self.appendcount > 40:
            # This check is to prevent any cases where there is a large number of unique appended extensions resulting in an overly large list
            newcount = len(self.newextensions)
            if newcount > 15:
                if ":" in self.description:
                    self.description += " overwrites_existing_files"
                else:
                    self.description += ": overwrites_existing_files"
                self.mbcs += ["OC0001", "C0015"]  # micro-behaviour
            ret = True

        return ret
