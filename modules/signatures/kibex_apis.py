# Copyright (C) 2015-2016 KillerInstinct
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

class Kibex_APIs(Signature):
    name = "kibex_behavior"
    description = "Exhibits behavior characteristic of Kibex Spyware/KeyBase Keylogger"
    severity = 3
    references = [
        "http://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_kibex.a",
        "http://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_kibex.i",
        "http://researchcenter.paloaltonetworks.com/2015/06/keybase-keylogger-malware-family-exposed/"
    ]
    categories = ["spyware", "keylogger"]
    families = ["kibex", "keybase"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.keylog_inits = 0
        self.c2s = set()

    filter_apinames = set(["SetWindowsHookExA", "WinHttpGetProxyForUrl"])

    def on_call(self, call, process):
        if call["api"] == "SetWindowsHookExA":
            hid = int(self.get_argument(call, "HookIdentifier"), 10)
            tid = int(self.get_argument(call, "ThreadId"), 10)
            if tid == 0 and hid == 13:
                self.keylog_inits += 1

        elif call["api"] == "WinHttpGetProxyForUrl":
            url = self.get_argument(call, "Url")
            if url and "&machine" in url.lower():
                self.c2s.add(url)

        return None

    def on_complete(self):
        bad_score = self.keylog_inits
        file_iocs = [
            ".*\\\\ProgramData\\\\Browsers\.txt$",
            ".*\\\\ProgramData\\\\Mails\.txt$",
            ".*\\\\Temp\\\\\d{9,10}\.xml$",
        ]
        for ioc in file_iocs:
            match = self.check_file(pattern=ioc, regex=True)
            if match:
                bad_score += 3

        stealer_regkeys = [
            ".*\\\\Google\\\\Google\\ Talk\\\\Accounts$",
            ".*\\\\Google\\\\Google\\ Desktop\\\\Mailboxes$",
            ".*\\\\Microsoft\\\\Internet\\ Account\\ Manager\\\\Accounts$",
        ]
        for ioc in stealer_regkeys:
            match = self.check_key(pattern=ioc, regex=True)
            if match:
                bad_score += 1

        services = [
            "ProtectedStorage",
            "VaultSvc",
        ]
        for service in services:
            if self.check_started_service(service):
                bad_score += 1

        if bad_score >= 10:
            for c2 in self.c2s:
                self.data.append({"C2": c2})

            return True

        return False
