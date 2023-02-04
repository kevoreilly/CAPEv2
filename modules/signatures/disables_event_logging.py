# Copyright (C) 2020 bartblaze
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


class DisablesEventLogging(Signature):
    name = "disables_event_logging"
    description = "Disables Event Logging"
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.002"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112", "F0004"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\System\\\\CurrentControlSet\\\\Control\\\\WMI\\\\Autologger\\\\EventLog-.*",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
