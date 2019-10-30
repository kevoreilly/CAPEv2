# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
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

class ModifyProxy(Signature):
    name = "modify_proxy"
    description = "Attempts to modify proxy settings"
    severity = 3
    categories = ["browser"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"

    filter_analysistypes = set(["file"])

    def run(self):
        # will need to turn this into an evented signature later, as IE will read the existing value of some of these entries
        # and write them back as the same value
        reg_indicators = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\ProxyEnable$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\ProxyServer$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\ZoneMap\\\\ProxyBypass$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\ProxyOverride$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\Wpad\\\\.*",
        ]
        whitelist = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\Wpad\\\\WpadLastNetwork$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\Wpad\\\\[^\\\\]*\\\\WpadDecisionReason$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\Wpad\\\\[^\\\\]*\\\\WpadDecisionTime$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\Wpad\\\\[^\\\\]*\\\\WpadDecision$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\Wpad\\\\[^\\\\]*\\\\WpadNetworkName$",
        ]
        # Get rid of a PDF false positive
        if "file" in self.results["target"]:
            if "PDF" in self.results["target"]["file"]["type"] or self.results["info"]["package"] == "pdf":
                del reg_indicators[0]

        for indicator in reg_indicators:
            matches = self.check_write_key(pattern=indicator, regex=True, all=True)
            if matches:
                for match in matches:
                    foundwhite = False
                    for white in whitelist:
                        if re.match(white, match, re.IGNORECASE):
                            foundwhite = True
                    if not foundwhite:
                        return True

        return False

