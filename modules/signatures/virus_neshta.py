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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class NeshtaMutexes(Signature):
    name = "neshta_mutexes"
    description = "Creates known Neshta virus mutexes"
    severity = 3
    categories = ["virus"]
    families = ["Neshta"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "MutexPolesskayaGlush.*",
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False

class NeshtaRegKeys(Signature):
    name = "neshta_regkeys"
    description = "Creates known Neshta virus registry keys"
    severity = 3
    weight = 3
    categories = ["virus"]
    families = ["neshta"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
    
    filter_apinames = set(["RegSetValueExA","RegSetValueExW"])

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            key = self.get_argument(call, "FullName").lower()
            if ".*\\software\\classes\\exefile\\shell\\open\\command.*" in key:
                buf = self.get_argument(call, "Buffer").lower()
                if re.match(r"^c:\\windows\\svchost.com\ \"%1\"\ %\*$", buf):
                    self.match = True
        return None

    def on_complete(self):
        if self.match:
            return True

        return False

class NeshtaFiles(Signature):
    name = "neshta_files"
    description = "Creates known Neshta virus file artifacts"
    severity = 3
    weight = 3
    categories = ["virus"]
    families = ["neshta"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    filter_apinames = set(["NtCreateFile"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateFile":
            filename = self.get_argument(call, "FileName").lower()
            if filename and "c:\\windows\\svchost.com" in filename:
                return True
        return None

    def on_complete(self):
        if self.match:
            return True
        
        return False