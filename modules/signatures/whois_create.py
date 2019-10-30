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
except:
    import re

from datetime import date
from datetime import datetime
from lib.cuckoo.common.abstracts import Signature

class WHOIS_Create(Signature):
    name = "whois_create"
    description = "The target URL domain was recently created. ({0} days ago)"
    severity = 2
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        ret = False
        timestrs = list()
        if "static" in self.results and self.results["static"]:
            if "url" in self.results["static"] and self.results["static"]["url"]:
                if "whois" in self.results["static"]["url"] and self.results["static"]["url"]["whois"]:
                    p = r".*Creation Date:(?P<Dates>.*)Updated Date:"
                    buf = re.match(p, self.results["static"]["url"]["whois"], re.DOTALL)
                    if buf:
                        timestrs = buf.group("Dates").split()[0::2]
        if timestrs:
            earliest = None
            for time in timestrs:
                if time == "None":
                    continue
                try:
                    buf = datetime.strptime(time, "%Y-%m-%d")
                except:
                    buf = datetime.strptime(time, "%Y/%m/%d")
                if not earliest:
                    earliest = buf
                    continue
                if buf < earliest:
                    earliest = buf

            if not earliest:
                return False
                
            earliest = earliest.date()

            # Some oddities observed, try/except to find a valid time
            try:
                buf = self.results["info"]["started"].split()[0]
            except:
                buf = self.results["info"]["machine"]["started_on"].split()[0]
            runtime = datetime.strptime(buf, "%Y-%m-%d").date()
            daycount = (runtime - earliest).days

            if daycount < 30:
                ret = True
                self.description = self.description.format(daycount)
                if daycount < 5:
                    self.severity += 1
                    self.weight += 1
                    grammar = "days"
                    if daycount == 1:
                        grammar = "day"
                    self.description = ("The target URL domain was created very"
                                        " recently. ({0} {1} ago)".format(
                                        daycount, grammar))
        return ret
