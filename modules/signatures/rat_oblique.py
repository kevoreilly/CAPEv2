# Copyright (C) 2020 ditekshen
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

class ObliquekRATMutexes(Signature):
    name = "obliquerat_mutexes"
    description = "Creates ObliqueRAT RAT mutexes"
    severity = 3
    categories = ["RAT"]
    families = ["ObliqueRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            "^Oblique$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class ObliquekRATFiles(Signature):
    name = "obliquerat_files"
    description = "Creates ObliqueRAT RAT directories and/or files"
    severity = 3
    categories = ["RAT"]
    families = ["ObliqueRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            ".*\\\\ProgramData\\\\System\\\\Dump.*",
            ".*\\\\ProgramData\\\\auto.txt$",
            ".*\\\\ProgramData\\\\a.txt$",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False

class ObliquekRATNetworkActivity(Signature):
    name = "obliquerat_network_activity"
    description = "Establishes ObliqueRAT RAT network activity"
    severity = 3
    categories = ["RAT"]
    families = ["ObliqueRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.username = self.get_environ_entry(self.get_initial_process(), "UserName")
        self.hostname = self.get_environ_entry(self.get_initial_process(), "ComputerName")
        self.match = False

    filter_apinames = set(["send"])

    def on_call(self, call, process):
        if call["api"] == "send":
            if self.hostname and self.username:
                buff = self.get_argument(call, "Buffer")
                if buff:
                    sysinfo = self.hostname + ">" + self.username + ">" + "Windows"
                    if buff.startswith(sysinfo) and "oblique" in buff:
                        self.data.append({"data": buff })
                        self.match = True

    def on_complete(self):
        return self.match
