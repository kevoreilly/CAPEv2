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

# https://capesandbox.com/analysis/67881/

from lib.cuckoo.common.abstracts import Signature


class UrsnifBehavior(Signature):
    name = "ursnif_behavior"
    description = "Ursnif Trojan behavior detected"
    severity = 3
    categories = ["trojan"]
    families = ["Ursnif"]
    authors = ["ditekshen"]
    minimum = "2.0"
    evented = True
    ttps = ["S0386"]  # MITRE

    def run(self):
        score = 0
        guid = "[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}"
        regpath = "HKEY_CURRENT_USER\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft"
        regkeys = [
            "Client",
            "Client32",
            "Client64",
        ]
        registry_indicators = []
        file_indicators = [".*\\\\mailslot\\\\[a-z]?(sl)[a-z0-9]{1,}$", ".*\\\\AppData\\\\Roaming\\\\Microsoft\\\\.*\\\\.*.dll$"]
        mutex_indicators = "^Local\\\\\{[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}\}$"

        for rkey in regkeys:
            registry_indicators.append(regpath + "\\\\" + guid + "\\\\" + rkey + "$")

        registry_indicators.append(
            ".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\EnableSPDY3_0$"
        )

        for rindicator in registry_indicators:
            match = self.check_write_key(pattern=rindicator, regex=True)
            if match:
                score += 1
                self.data.append({"regkey": match})
                self.ttps += ["T1112"]  # MITRE v6,7,8
                self.mbcs += ["E1112"]
                self.mbcs += ["OC0008", "C0036"]  # micro-behaviour

        for findicator in file_indicators:
            match = self.check_write_file(pattern=findicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})
                self.mbcs += ["OC0001", "C0052"]  # micro-behaviour

        mutex_match = self.check_mutex(pattern=mutex_indicators, regex=True, all=True)
        if mutex_match:
            if len(mutex_match) >= 2:
                score += 1
                self.data.append({"mutex": mutex_match})
                self.mbcs += ["OC0003", "C0042"]  # micro-behaviour

        if score > 4:
            return True

        return False
