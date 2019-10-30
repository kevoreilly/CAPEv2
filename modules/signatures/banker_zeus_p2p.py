# Copyright (C) 2014,2015 Robby Zeitfuchs (@robbyFux) Optiv, Inc. (brad.spengler@optiv.com)
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

class ZeusP2P(Signature):
    name = "banker_zeus_p2p"
    description = "Zeus P2P (Banking Trojan)"
    severity = 3
    categories = ["banker"]
    families = ["zeus"]
    authors = ["Robby Zeitfuchs", "Optiv"]
    minimum = "1.2"
    references = ["https://malwr.com/analysis/NmNhODg5ZWRkYjc0NDY0M2I3YTJhNDRlM2FlOTZiMjA/", 
                  "https://malwr.com/analysis/MmMwNDJlMTI0MTNkNGFjNmE0OGY3Y2I5MjhiMGI1NzI/",
                  "https://malwr.com/analysis/MzY5ZTM2NzZhMzI3NDY2YjgzMjJiODFkODZkYzIwYmQ/",
                  "https://www.virustotal.com/de/file/301fcadf53e6a6167e559c84d6426960af8626d12b2e25aa41de6dce511d0568/analysis/#behavioural-info",
                  "https://www.virustotal.com/de/file/d3cf49a7ac726ee27eae9d29dee648e34cb3e8fd9d494e1b347209677d62cdf9/analysis/#behavioural-info",
                  "https://www.virustotal.com/de/file/d3cf49a7ac726ee27eae9d29dee648e34cb3e8fd9d494e1b347209677d62cdf9/analysis/#behavioural-info",
                  "https://www.virustotal.com/de/file/301fcadf53e6a6167e559c84d6426960af8626d12b2e25aa41de6dce511d0568/analysis/#behavioural-info"]

    def run(self):
        # Check zeus synchronization-mutex.
        count = 0
        mutexes = self.check_mutex("^(Global|Local)\\\\\{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}\}", regex=True, all=True)
        if mutexes:
            count += len(mutexes)

        # Check if there are at least 5 mutexes opened matching the pattern?   
        if count < 5:
            return False

        # Check for UDP Traffic on remote port greater than 1024.
        # TODO: this might be faulty without checking whether the destination
        # IP is really valid.
        count = 0
        if "network" in self.results:
            for udp in self.results.get("network", {}).get("udp",[]):
                if udp["dport"] > 1024:
                    count += 1
            
        if count < 4:
            return False

        for mutex in mutexes:
            self.data.append({"mutex": mutex})

        return True
