# Copyright (C) 2014 Optiv Inc. (brad.spengler@optiv.com), Converted 2016 for Cuckoo 2.0
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


class DeletesExecutedFiles(Signature):
    name = "deletes_executed_files"
    description = "Deletes executed files from disk"
    severity = 3
    categories = ["persistence", "stealth"]
    # Migrated by @CybercentreCanada
    authors = ["Optiv", "Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    ttps = ["T1070"]
    evented = True

    def run(self):
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]

        if cmdlines:
            for deletedfile in self.results["behavior"]["summary"]["delete_files"]:
                if any(deletedfile in cmdline for cmdline in cmdlines):
                    self.data.append({"file": deletedfile})

        if len(self.data) > 0:
            return True
        else:
            return False
