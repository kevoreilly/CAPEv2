# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class Tor(Signature):
    name = "network_tor"
    description = "Installs Tor on the infected machine"
    severity = 3
    categories = ["network", "anonimity", "tor"]
    authors = ["nex"]
    minimum = "1.3"
    evented = True
    ttp = ["T1188"]

    filter_apinames = set(["CreateServiceA", "CreateServiceW"])

    def on_call(self, call, process):
        if self.check_argument_call(call,
                                    pattern="Tor Win32 Service",
                                    ignorecase=True):
            return True

    def on_complete(self):
        indicators = [
            ".*\\\\tor\\\\cached-certs$",
            ".*\\\\tor\\\\cached-consensus$",
            ".*\\\\tor\\\\cached-descriptors$",
            ".*\\\\tor\\\\geoip$",
            ".*\\\\tor\\\\lock$",
            ".*\\\\tor\\\\state$",
            ".*\\\\tor\\\\torrc$"
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator, regex=True):
                return True
