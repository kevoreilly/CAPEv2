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

class NemtyMutexes(Signature):
    name = "nemty_mutexes"
    description = "Creates Nemty ransomware mutexes"
    severity = 3
    categories = ["ransomware"]
    families = ["Nemty"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            "^hate$",
            "^just_a_little_game$",
            "^da mne pohui chto tebe tam.*",
            "^Vremya tik-tak.*"
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class NemtyRegkeys(Signature):
    name = "nemty_regkeys"
    description = "Creates Nemty ransomware registry keys"
    severity = 3
    categories = ["ransomware"]
    families = ["Nemty"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            "HKEY_CURRENT_USER\\\\Software\\\\NEMTY.*",
        ]

        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False

class NemtyNote(Signature):
    name = "nemty_note"
    description = "Creates Nemty ransomware note"
    severity = 3
    categories = ["ransomware"]
    families = ["Nemty"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    filter_apinames = set(["NtWriteFile"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        handle = self.get_argument(call, "HandleName")
        if buff and handle:
            if "NEMTY PROJECT" in buff and handle.endswith(".txt"):
                self.match = True

    def on_complete(self):
        return self.match

class NemtyNetworkActivity(Signature):
    name = "nemty_network_activity"
    description = "Establishes Nemty ransomware network activity to look up external IP address"
    severity = 3
    categories = ["ransomware"]
    families = ["Nemty"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match_agent = False
        self.match_domain = False
        self.useragents = [
            "Chrome",
            "Nemty",
        ]
        self.domains = [
            "api.ipify.org",
            "api.db-ip.com",
        ]

    filter_apinames = set(["InternetOpenA", "InternetOpenUrlA"])

    def on_call(self, call, process):
        if call["api"] == "InternetOpenA":
            agent = self.get_argument(call, "Agent")
            if agent:
                for ua in self.useragents:
                    if ua.lower() == agent.lower():
                        self.match_agent = True

        if call["api"] == "InternetOpenUrlA":
            url = self.get_argument(call, "URL")
            if url:
                for domain in self.domains:
                    if domain in url:
                        self.match_domain

    def on_complete(self):
        if self.match_agent and self.match_domain:
            return True

        return False