# Copyright (C) 2019 ditekshen
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

class MasqueradesProcessName(Signature):
    name = "masquerade_process_name"
    description = "Attempts to masquerade or mimic a legitimate process or file name"
    severity = 3
    categories = ["masquerading", "evasion", "execution"]
    families = [""]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttp = ["T1036"]
    evented = True

    def run(self):
        indicators = [
            ".*svhost\.(exe|dll)$",
            ".*svhhost\.(exe|dll)$",
            ".*svvhost\.(exe|dll)$",
            ".*srvhost\.(exe|dll)$",
            ".*swchost\.(exe|dll)$",
            ".*svvhost\.(exe|dll)$",
            ".*svchosts\.(exe|dll)$",
            ".*svch0st\.(exe|dll)$",
            ".*skhosts\.(exe|dll)$",
            ".*svhoost\.(exe|dll)$",
            ".*scvhost\.(exe|dll)$",
            ".*svschost\.(exe|dll)$",
            ".*svchostt\.(exe|dll)$",
            ".*spoolsrv\.(exe|dll)$",
            ".*spoolsvc\.(exe|dll)$",
            ".*spoolscv\.(exe|dll)$",
            ".*dllh0st\.(exe|dll)$",
            ".*taskh0st\.(exe|dll)$",
        ]

        for indicator in indicators:
            procmatch = self.check_process_name(pattern=indicator)
            if procmatch:
                self.data.append({"process": procmatch})
                return True
            filematch = self.check_file(pattern=indicator, regex=True)
            if filematch:
                self.data.append({"file": filematch})
                return True
            wfilematch = self.check_write_file(pattern=indicator, regex=True)
            if wfilematch:
                self.data.append({"file": wfilematch})
                return True

        return False 
