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

# https://capesandbox.com/analysis/67867/

from lib.cuckoo.common.abstracts import Signature


class AddsAdminUser(Signature):
    name = "adds_admin_user"
    description = "Adds a new user to the Administrators group"
    severity = 3
    categories = ["account"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1136"]  # MITRE v6,7,8
    ttps += ["T1136.001"]  # MITRE v7,8

    def run(self):
        indicators = ".*net(\.exe)?.*localgroup\sadministrators.*/add"

        match = self.check_executed_command(pattern=indicators, regex=True)
        if match:
            self.data.append({"command": match})
            return True

        return False


class OverwritesAdminPassword(Signature):
    name = "overwrites_admin_password"
    description = "Overwrites local Administrator password"
    severity = 3
    categories = ["account"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1098"]  # MITRE v6,7,8

    def run(self):
        indicators = ".*net(\.exe)?.*user\sadministrator\s.*"

        match = self.check_executed_command(pattern=indicators, regex=True)
        if match:
            self.data.append({"command": match})
            return True

        return False


class AddsUser(Signature):
    name = "adds_user"
    description = "Adds a new user to the system"
    severity = 2
    categories = ["account"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1136"]  # MITRE v6,7,8
    ttps += ["T1136.001"]  # MITRE v7,8

    def run(self):
        indicators = ".*net(1)?(\.exe)?\suser\s[^administrator(s)?\s].*/add"

        match = self.check_executed_command(pattern=indicators, regex=True)
        if match:
            self.data.append({"command": match})
            return True

        return False
