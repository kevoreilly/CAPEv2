# Copyright (C) 2015 KillerInstinct
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

class KazyBot_APIs(Signature):
    name = "kazybot_behavior"
    description = "Exhibits behavior characteristics of KazyBot RAT"
    severity = 3
    weight = 3
    categories = ["rat"]
    families = ["kazybot"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.postreq = False
        self.score = 0

    filter_apinames = set(["send"])

    def on_call(self, call, process):
        buf = self.get_argument(call, "buffer")
        if self.postreq:
            if "HWID=" in buf:
                if "DATA=" in buf or "SERVER=" in buf or "PASSWORD=" in buf:
                    self.score += 1
        if re.match("POST\s/[^\.]+\.php", buf):
            self.postreq = True
        else:
            self.postreq = False

        return None

    def on_complete(self):
        module_paths = [
            ".*\\\\SharedCode\\\\SharedCode.dll$",
            ".*\\\\SharedCode\\\\SharedCode.exe$",
            ".*\\\\PluginServer\\\\PluginServer.dll$",
            ".*\\\\PluginServer\\\\PluginServer.exe$",
        ]
        for indicator in module_paths:
            if self.check_file(pattern=indicator, regex=True):
                self.score += 3

        if self.score >= 10:
            return True

        return False
