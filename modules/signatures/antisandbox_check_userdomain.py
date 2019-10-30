# Copyright (C) 2019 enzok
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

class AntiSandboxCheckUserdomain(Signature):
    name = "antisandbox_check_userdomain"
    description = "Checks userdomain environment variable using VBE environ function"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["enzok"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["rtcEnvironBstr"])

    def on_call(self, call, process):
        if call["api"] == "rtcEnvironBstr":
            envvar = self.get_argument(call, "EnvVar")
            if envvar == "userdomain":
                return True
        else:
            return False
