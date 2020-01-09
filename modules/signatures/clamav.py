# Copyright (C) 2015 Will Metcalf (william.metcalf@gmail.com)
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

class ClamAV(Signature):
    name = "clamav"
    description = "Clamav Hits in Target/Dropped/SuriExtracted"
    severity = 3
    weight = 0 
    categories = ["clamav"]
    authors = ["Will Metcalf"]
    minimum = "1.2"

    def run(self):
        clam_no_score_re = re.compile(r'^(SaneSecurity\.FoxHole|MiscreantPunch\.(?:Susp|INFO))',re.I)
        clam_ignore = ['PhishTank.Phishing.6117523.UNOFFICIAL']
        self.data = []
        if self.results["target"]["category"] == "file":
            if "clamav" in self.results["target"]["file"].keys() and self.results["target"]["file"]["clamav"] and "sha256" in self.results["target"]["file"].keys():
                for detection in self.results["target"]["file"]["clamav"]:
                    entry = "%s, target" % (detection)
                    if detection in clam_ignore:
                        continue
                    if not clam_no_score_re.search(detection):
                        self.weight = 3
                    if "type" in self.results["target"]["file"]:
                        entry = "%s, type:%s" % (entry,self.results["target"]["file"]["type"])
                    self.data.append({self.results["target"]["file"]["sha256"]: entry})

        if "suricata" in self.results and self.results["suricata"]:
            if "files" in self.results["suricata"]:
                for entry in self.results["suricata"]["files"]:
                    proto = entry["protocol"]
                    if "clamav" in entry["file_info"].keys() and entry["file_info"]["clamav"] and "sha256" in entry["file_info"].keys():
                        for detection in entry["file_info"]["clamav"]:
                            if detection in clam_ignore:
                                continue
                            if not clam_no_score_re.search(detection):
                                self.weight = 3
                            lentry = "%s, suricata_extracted_files, src:%s, sp:%s, dst:%s, dp:%s" % (detection,entry['srcip'], entry['sp'],entry['dstip'],entry['dp'])
                            if "http_user_agent" in entry.keys():
                                lentry  = "%s, ua:%s" % (lentry, entry['http_user_agent'])
                            if "http_uri" in entry.keys():
                                lentry =  "%s, uri:%s" % (lentry,entry['http_uri'])
                            if "http_referer" in entry.keys():
                                lentry = "%s, referer:%s" % (lentry,entry['http_referer'])
                            if entry["file_info"]["type"]:
                                lentry =  "%s, type:%s" % (lentry,entry["file_info"]["type"])
                            self.data.append({entry["file_info"]["sha256"]: lentry})
                            
        if "dropped" in self.results:
            for entry in self.results["dropped"]:
                if "clamav" in entry.keys() and entry["clamav"] and "sha256" in entry.keys():
                    for detection in entry["clamav"]:
                        if detection in clam_ignore:
                            continue
                        if not clam_no_score_re.search(detection):
                            self.weight = 3
                        lentry = "%s, dropped" % (detection)
                        if "guest_paths"  in entry.keys():
                            lentry = "%s, guest_paths:%s" % (lentry,"*".join(entry["guest_paths"]))
                        if "type" in entry.keys():
                            lentry = "%s, type:%s" % (lentry,entry["type"])
                        self.data.append({entry["sha256"]: lentry})

        if len(self.data) > 0:
            return True

        return False

