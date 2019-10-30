# Copyright (C) 2018 Kevin Ross
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

class ClearsLogs(Signature):
    name = "clears_logs"
    description = "Clears Windows events or logs"
    severity = 3
    confidence = 50
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        file_indicators = [
            ".*\\\\Windows\\\\Logs.*",
            ".*\\\\inetpub\\\\logs\\\\LogFiles.*",
            ".*\\\\Windows\\\\System32\\\\Winevt.*",
            ".*\.etl$",
            ".*\.evt$",
            ".*\.evtx$",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            if "wevtutil" in cmdline.lower() and "cl" in cmdline.lower():
                self.data.append({"command" : cmdline})
                ret = True

        for indicator in file_indicators:
            match_file = self.check_delete_file(pattern=indicator, regex=True, all=True)
            if match_file:
                for match in match_file:
                    self.data.append({"file" : match})
                ret = True        

        return ret
