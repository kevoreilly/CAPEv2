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
    # apt-get install libpcre3-dev
    # build + install https://github.com/awahlig/python-pcre
    import pcre
    HAVE_PCRE = True
except ImportError:
    HAVE_PCRE = False

from lib.cuckoo.common.abstracts import Signature

class PunchPlusPlusPCREs(Signature):
    name = "punch_plus_plus_pcres"
    description = "Punch++ PCRE hit on an HTTP request"
    severity = 3
    weight = 2
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        if not HAVE_PCRE:
            return False

        ret = False
        pcres = list()
        kits = [
            "angler",
            "dotcachef",
            "fiesta",
            "goon",
            "magnitude",
            "neutrino",
            "nuclear",
            "orange",
            "rig",
        ]
        office = [
            "doc",
            "xls",
            "ppt",
        ]
        if "feeds" in self.results and self.results["feeds"]:
            if "Punch_Plus_Plus_PCREs" in self.results["feeds"]:
                with open(self.results["feeds"]["Punch_Plus_Plus_PCREs"], "r") as feedfile:
                    data = feedfile.read().splitlines()
                if data:
                    for item in data:
                        regex = item.split()[0]
                        desc = " ".join(item.split()[1:])
                        pcres.append((regex, desc))

        if "network" in self.results and self.results["network"]:
            if "http" in self.results["network"] and self.results["network"]["http"]:
                for req in self.results["network"]["http"]:
                    for regex in pcres:
                        if pcre.match(regex[0], req["uri"]):
                            ret = True
                            add = {"URL": req["uri"]}
                            if add not in self.data:
                                self.data.append(add)
                            self.data.append({"Desc": regex[1]})
                            self.data.append({"PCRE": regex[0]})
                            for ek in kits:
                                check1 = " {0} ek".format(ek)
                                check2 = " {0} exploit kit".format(ek)
                                desc = regex[1].lower()
                                if check1 in desc or check2 in desc:
                                    if ek not in self.families:
                                        self.families = [ek]
                                if self.results["info"]["package"] in office:
                                    if "dridex" in regex[1].lower() and "dridex" not in self.families:
                                        if not self.families:
                                            self.families = ["dridex"]

        if ret:
            return True

        return False
