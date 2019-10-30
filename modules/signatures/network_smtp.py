# Copyright (C) 2013-2016 Claudio "nex" Guarnieri (@botherder), KillerInstinct
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

class NetworkSMTP(Signature):
    name = "network_smtp"
    description = "Makes SMTP requests, possibly sending spam or exfiltrating data."
    severity = 3
    categories = ["smtp", "spam"]
    authors = ["nex", "KillerInstinct"]
    minimum = "0.5"

    def run(self):
        if "network" in self.results:
            if "smtp" in self.results["network"]:
                if len(self.results["network"]["smtp"]) > 0:
                    for mail in self.results["network"]["smtp"]:
                        sentToIP = mail["dst"]
                        sentToDomain = str()
                        for name in self.results["network"].get("dns", []):
                            if name["answers"]:
                                for ip in name["answers"]:
                                    if ip["data"] == sentToIP:
                                        sentToDomain = name["request"]
                        desc = sentToIP
                        if sentToDomain:
                            desc += " (%s)" % str(sentToDomain)
                        self.data.append({"SMTP": desc})

                    return True

        return False
