# Copyright (C) 2016 Kevin Ross
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

class FamilyProxyBack(Signature):
    name = "family_proxyback"
    description = "Exhibits behavior characteristic of Proxyback malware"
    severity = 3
    families = ["proxyback"]
    authors = ["Kevin Ross"]
    references = ["http://researchcenter.paloaltonetworks.com/2015/12/proxyback-malware-turns-user-systems-into-proxies-without-consent/"]
    minimum = "1.2"

    def run(self):
        mutexes = [
            "PB_MAIN_MUTEX_GL_.*",
            "PB_SN_MUTEX_GL_.*",
            "PB_SCH_MUTEX_GL_.*"
        ]

        for mutexes in mutexes:
            if self.check_mutex(pattern=mutexes, regex=True):
                return True

        if "network" in self.results and "http" in self.results["network"]:
            for req in self.results["network"]["http"]:
                if "User-Agent: pb" in req["data"]:
                    return True

        return False
