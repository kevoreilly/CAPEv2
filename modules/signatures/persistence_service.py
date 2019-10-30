# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free Software: you can redistribute it and/or modify
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

class PersistenceService(Signature):
    name = "persistence_service"
    description = "Created a service that was not started"
    severity = 3
    categories = ["persistence"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        found = False
        created_services = set(self.results["behavior"]["summary"]["created_services"])
        started_services = set(self.results["behavior"]["summary"]["started_services"])
        missing = created_services.difference(started_services)
        if missing:
            for service in missing:
                self.data.append({"service" : service })
            found = True
        return found