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

class Secure_Login_Phish(Signature):
    name = "secure_login_phish"
    description = "'{0}' in HTML Title but connection is not HTTPS. Possibly indicative of phishing."
    severity = 2
    categories = ["phish"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lasturl = str()
        self.phishurls = set()

    filter_apinames = set(["InternetCrackUrlW", "InternetReadFile"])

    def on_call(self, call, process):
        if call["api"] == "InternetCrackUrlW":
            url = self.get_argument(call, "Url")
            if url:
                self.lasturl = url
        elif call["api"] == "InternetReadFile":
            buf = self.get_argument(call, "Buffer")
            if buf and not self.lasturl.startswith("https"):
                if "<title>" in buf:
                    if re.search("<title>\s*Secure\s*Login\s*</t", buf, re.I):
                        self.phishurls.add(self.lasturl)
                        self.description = self.description.format("Secure Login")
                    elif re.search("<title>Goog[li]e\sDoc.*</t", buf, re.I):
                        self.phishurls.add(self.lasturl)
                        self.description = self.description.format("Google Doc")
                    elif re.search("<title>\s*Dropbox.*</t", buf, re.I):
                        self.phishurls.add(self.lasturl)
                        self.description = self.description.format("Dropbox")
                    elif re.search("<title>Goog[li]e\sDrive.*</t", buf, re.I):
                        self.phishurls.add(self.lasturl)
                        self.description = self.description.format("Google Drive")

    def on_complete(self):
        if self.phishurls:
            for url in self.phishurls:
                self.data.append({"URL": url})
            return True

        return False
