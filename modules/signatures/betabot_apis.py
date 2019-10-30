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

class BetaBot_APIs(Signature):
    name = "betabot_behavior"
    description = "Exhibits behavior characteristics of BetaBot / Neurevt malware"
    severity = 3
    weight = 3
    categories = ["trojan"]
    families = ["betabot", "neurevt"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.events = set()
        self.postreqs = set()

    filter_apinames = set(["NtCreateEvent", "NtOpenEvent", "HttpSendRequestA"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateEvent" or call["api"] == "NtOpenEvent":
            self.events.add(self.get_argument(call, "EventName"))
        elif call["api"] == "HttpSendRequestA":
            if str(process["module_path"]).lower() == "c:\\windows\\explorer.exe":
                buf = self.get_argument(call, "PostData")
                if buf:
                    self.postreqs.add(buf)
        return None

    def on_complete(self):
        malscore = 0
        # Check for ADS deletion path (Always in hidden ProgramData)
        # TODO: make this use environ info
        ads_paths = [
            "C:\\\\ProgramData\\\\.*:Zone\.Identifier$",
            "C:\\\\Program\\ Files\\\\Common\\ Files\\\\Microsoft\\\\.*:Zone\.Identifier$"
        ]
        for indicator in ads_paths:
            if self.check_delete_file(pattern=indicator, regex=True):
                malscore += 3

        # Check for known filesystem behavior
        # TODO: make these use environ info
        file_paths = [
            ".*\\\\jagexcache$",
            ".*\\\\AppData\\\\Roaming\\\\\.minecraft$",
            ".*\\\\Application\\ Data\\\\\.minecraft$",
            ".*\\\\League\\ of\\ Legends$",
        ]
        for indicator in file_paths:
            if self.check_file(pattern=indicator, regex=True):
                malscore += 1

        # Check for known registry behavior
        reg_paths = [
            ".*\\\\SOFTWARE\\\\Classes\\\\origin$",
            ".*\\\\SOFTWARE\\\\Blizzard\\ Entertainment$",
        ]
        for indicator in reg_paths:
            if self.check_key(pattern=indicator, regex=True):
                malscore += 1

        # Check for known event pattern
        for ev in self.events:
            if re.search(r":[A-F0-9]{32}_0x[A-F0-9]{8}_", ev):
                malscore += 5
                break

        # Check for explorer.exe POST requests
        if len(self.postreqs) > 0:
            malscore += 3

        # Trigger if we match enough of the indicators
        if malscore >= 10:
            return True

        return False
