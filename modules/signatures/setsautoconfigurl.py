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
except:
    import re

from lib.cuckoo.common.abstracts import Signature

class SetsAutoconfigURL(Signature):
    name = "sets_autoconfig_url"
    description = "Sets an Autoconfig URL, likely to hijack browser settings."
    severity = 3
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pathbuf = str()
        self.keybuf = str()
        self.configpath = (r"^[A-Za-z]:\\.*\\Mozilla\\Firefox\\Profiles\\.*\\"
                            "prefs\.js")
        self.configkey = (r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\"
                          r"CurrentVersion\\Internet Settings\\AutoConfigURL")

    filter_apinames = set(["RegSetValueExA", "NtWriteFile"])

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            key = self.get_argument(call, "FullName")
            if key and re.match(self.configkey, key):
                value = self.get_argument(call, "ValueName").lower()
                if value == "autoconfigurl":
                    self.keybuf = self.get_argument(call, "Buffer")

        elif call["api"] == "NtWriteFile":
            path = self.get_argument(call, "HandleName")
            if path and re.match(self.configpath, path):
                buf = self.get_argument(call, "Buffer")
                if "user_pref" in buf and "network.proxy.autoconfig_url" in buf:
                    tmp = buf.split("(")[1].split(")")[0].split(",")[1]
                    self.pathbuf = tmp.strip().replace("\"","").replace("'","")

    def on_complete(self):
        ret = False
        if self.keybuf:
            self.data.append({"InternetSettings": self.keybuf})
            ret = True
        if self.pathbuf:
            self.data.append({"MozillaSettings": self.pathbuf})
            ret = True

        return ret
