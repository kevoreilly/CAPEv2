# Copyright (C) 2018 Kevin Ross
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

import re

from lib.cuckoo.common.abstracts import Signature

class CryptominingStratumCommand(Signature):
    name = "cyrptomining_stratum_command"
    description = "A cryptomining command was executed"
    severity = 3
    confidence = 90
    categories = ["cryptomining"]
    authors = ["Kevin Ross", "Cuckoo Technologies"]
    minimum = "1.3"
    evented = True
    references = ["blog.talosintelligence.com/2018/01/malicious-xmr-mining.html", "www.fireeye.com/blog/threat-research/2018/07/cryptocurrencies-cyber-crime-growth-of-miners.html"]
    ttp = ["T1496"]

    def run(self):
        xmr_address_re = '-u[ ]*4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}'
        xmr_strings = ["stratum+tcp://", "xmrig", "xmr-stak", "supportxmr.com:", "dwarfpool.com:", "minergate", "xmr.", "monero."]

        ret = False
        for cmdline in self.results["behavior"]["summary"]["executed_commands"]:
            if re.search(xmr_address_re, cmdline):
                self.data.append({"command" : cmdline })
                ret = True
            for xmr_string in xmr_strings:
                if xmr_string in cmdline.lower():
                    self.data.append({"command" : cmdline })
                    ret = True

        return ret
