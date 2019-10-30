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

class MartiansOffice(Signature):
    name = "office_martian_children"
    description = "Martian Subprocess Started By Office Process"
    severity = 3
    weight = 3
    categories = ["martians"]
    authors = ["Will Metcalf"]
    minimum = "1.3"
    ttp = ["T1059"]

    def go_deeper(self, pdict, result=None):
        if result is None:
            result = []
        result.append(pdict["module_path"].lower())
        for e in pdict["children"]:
            self.go_deeper(e, result)
        return result

    def find_martians(self,ptree,pwlist):
       result = []
       if ptree["children"]:
           children = self.go_deeper(ptree)
           for child in children:
               match_found = False
               for entry in pwlist:
                   if entry.search(child):
                       match_found = True
               if not match_found:
                   result.append(child)
       return result

    def run(self):
        if self.results["target"]["category"] == "url":
            return False

        office_pkgs = ["ppt","doc","xls","eml"]
        if not any(e in self.results["info"]["package"] for e in office_pkgs):
            return False

        self.office_paths_re = re.compile(r"^[A-Z]\:\\Program Files(?:\s\(x86\))?\\Microsoft Office\\(?:Office1[1-5]\\)?(?:WINWORD|OUTLOOK|POWERPNT|EXCEL|WORDVIEW)\.EXE$",re.I)
        #run through re.escape()
        #############################################
        #YOU MAY HAVE TO CUSTOMIZE THIS FOR YOUR ENV#
        #############################################
        self.white_list_re = ["C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Adobe\\\\Reader\\ \\d+\\.\\d+\\\\Reader\\\\AcroRd32\\.exe$",
                         "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Java\\\\jre\\d+\\\\bin\\\\j(?:avaw?|p2launcher)\\.exe$",
                         "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Microsoft SilverLight\\\\(?:\\d+\\.)+\\d\\\\agcp\\.exe$",
                         "C\\:\\\\Windows\\\\System32\\\\ntvdm\\.exe$",
                         "C\\:\\\\Windows\\\\System32\\\\svchost\\.exe$",
                         "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\internet explorer\\\\iexplore\.exe$",
                         # remove this one at some point
                         "C\\:\\\\Windows\\\\System32\\\\rundll32\\.exe$",
                         "C\\:\\\\Windows\\\\System32\\\\drwtsn32\\.exe$",
                         "C\\:\\\\Windows\\\\splwow64\\.exe$",
                         "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Common Files\\\\Microsoft Shared\\\\office1[1-6]\\\\off(?:lb|diag)\\.exe$",
                         "C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Common Files\\\\Microsoft Shared\\\\dw\\\\dw(?:20)?\\.exe$",
                         "C\\:\\\\Windows\\\\system32\\\\dwwin\\.exe$",
                         "C\\:\\\\Windows\\\\system32\\\\WerFault\\.exe$",
                         "C\\:\\\\Windows\\\\syswow64\\\\WerFault\\.exe$"
                        ]
        #means we can be evaded but also means we can have relatively tight paths between 32-bit and 64-bit
        self.white_list_re_compiled = []
        for entry in self.white_list_re:
            try:
                self.white_list_re_compiled.append(re.compile(entry,re.I))
            except Exception as e:
                print "failed to compile expression %s error:%s" % (entry,e)
        self.white_list_re_compiled.append(self.office_paths_re)

        # Sometimes if we get a service loaded we get out of order processes in tree need iterate over IE processes get the path of the initial monitored executable
        self.initialpath = None
        processes = self.results["behavior"]["processtree"]
        if len(processes):
            for p in processes:
                initialpath = p["module_path"].lower()
                if initialpath and self.office_paths_re.match(initialpath) and p.has_key("children"):
                    self.martians = self.find_martians(p,self.white_list_re_compiled)
                    if len(self.martians) > 0:
                        for martian in self.martians:
                            self.data.append({"office_martian": martian})
                        return True
        return False

