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

from lib.cuckoo.common.abstracts import Signature


class DisableRunCommand(Signature):
    name = "disables_run_command"
    description = (
        "Attempts to disable or modify the Run command from the Start menu and the New Task (Run) command from Task Manager"
    )
    severity = 3
    categories = ["generic"]
    authors = ["ditekshen"]
    minimum = "0.5"
    ttps = ["T1112"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\NoRun.*",
        ]

        for indicator in indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True)
            cmd_match = self.check_executed_command(pattern=indicator, regex=True)
            if reg_match:
                self.data.append({"regkey": reg_match})
                return True
            elif cmd_match:
                self.data.append({"command": cmd_match})
                return True

        return False
