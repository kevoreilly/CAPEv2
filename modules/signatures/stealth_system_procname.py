# Copyright (C) 2017 Kevin Ross
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


class StealthSystemProcName(Signature):
    name = "stealth_system_procname"
    description = "Created a process named as a common system process"
    severity = 2
    categories = ["stealth"]
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    ttps = ["T1036"]
    evented = True

    filter_apinames = set(["CreateProcessInternalW", "ShellExecuteExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.systemprocs = [
            "csrss.exe",
            "explorer.exe",
            "lsass.exe",
            "spoolsv.exe",
            "services.exe",
            "svchost.exe",
            "taskmgr.exe",
            "winlogin.exe",
        ]

    def on_call(self, call, _):
        filepath = self.get_argument(call, "filepath")
        if filepath:
            filepath = filepath.lower()
        else:
            return False
        for systemproc in self.systemprocs:
            if filepath.endswith(systemproc):
                if not filepath.endswith("svchost.exe"):
                    self.severity = 3
                if self.pid:
                    self.mark_call()
                return True
