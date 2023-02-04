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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

user_agent = re.compile(
    "(?i)((%(25){0,}20|\s)*(%(25){0,}24|\$)(%(25){0,}20|\s)*(%(25){0,}7B|{){0,1}(%(25){0,}20|\s)*(%(25){0,}(6A|4A)|J)(%(25){0,}(6E|4E)|N)(%(25){0,}(64|44)|D)(%(25){0,}(69|49)|I)(%(25){0,}20|\s)*(%(25){0,}3A|:)[\w\%]+(%(25){1,}3A|:)(%(25){1,}2F|\/)|\$((::-[A-Z%]}\$){1,}|(ENV|LOWER|UPPER):).+[:}]{2}\/)[^\n]+"
)


class Log4j(Signature):
    name = "log4shell"
    description = "Log4Shell"
    severity = 3
    categories = ["malware"]
    authors = ["Busra Yenidogan"]
    minimum = "0.5"
    enabled = False

    def run(self):
        httpitems = self.results.get("network", {}).get("http", [])
        for http in httpitems:
            if user_agent.search(http.get("data", "")):
                self.data.append({"url": http["uri"], "user-agent": http.get("user-agent", ""), "data": http["data"]})
                return True

        return False
