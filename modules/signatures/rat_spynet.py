# Copyright (C) 2014,2016 @threatlead, Brad Spengler
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

class SpynetRat(Signature):
    name = "rat_spynet"
    description = "Creates known SpyNet mutexes and/or registry changes."
    severity = 3
    categories = ["rat"]
    families = ["spynet"]
    authors = ["threatlead", "nex", "Brad Spengler"]
    references = [
        "https://malwr.com/analysis/ZDQ1NjBhNWIzNTdkNDRhNjhkZTFmZTBkYTU2YjMwNzg/",
        "https://malwr.com/analysis/MjkxYmE2YzczNzcwNGJiZjljNDcwMzA2ZDkyNDU2Y2M/",
        "https://malwr.com/analysis/N2E3NWRiNDMyYjIwNGE0NTk3Y2E5NWMzN2UwZTVjMzI/",
        "https://malwr.com/analysis/N2Q2NWY0Y2MzOTM0NDEzNmE1MTdhOThiNTQxMzhiNzk/"   
    ]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*CYBERGATEUPDATE",
            ".*\(\(SpyNet\)\).*",
            ".*Spy-Net.*",
            ".*X_PASSWORDLIST_X.*",
            ".*X_BLOCKMOUSE_X.*",
            #".*PERSIST", # Causes false positive detection on XtremeRAT samples.
            ".*_SAIR",
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        keys = [
            ".*\\\\SpyNet\\\\.*",
        ]
        whitelist = [
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\.*",
        ]
        for key in keys:
            keymatch = self.check_write_key(pattern=key, regex=True)
            if keymatch:
                is_good = True
                for white in whitelist:
                    if re.match(white, keymatch, re.IGNORECASE):
                        is_good = False
                        break
                if is_good:
                    return True
        
        return False
