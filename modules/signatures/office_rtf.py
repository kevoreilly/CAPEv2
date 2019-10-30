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

from lib.cuckoo.common.abstracts import Signature

class RTFEmbeddedContent(Signature):
    name = "rtf_embedded_content"
    description = "The RTF file contains embedded content"
    severity = 1
    confidence = 100
    categories = ["rtf", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        if "static" in self.results and "office_rtf" in self.results["static"]:
            for key in self.results["static"]["office_rtf"]:
                for block in self.results["static"]["office_rtf"][key]:
                    if "type_embed" in block:
                        index = block["index"]
                        classname = block["class_name"]
                        size = block["size"]
                        self.data.append({"embedded content" : "Object %s index %s contains embedded object %s with size %s bytes" % (key,index,classname,size)})
                        ret = True

        return ret

class RTFExploitStatic(Signature):
    name = "rtf_exploit_static"
    description = "The RTF file contains an object with potential exploit code"
    severity = 3
    confidence = 100
    categories = ["exploit", "office", "rtf", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        if "static" in self.results and "office_rtf" in self.results["static"]:
            for key in self.results["static"]["office_rtf"]:
                for block in self.results["static"]["office_rtf"][key]:
                    if "CVE" in block:
                        index = block["index"]
                        cve = block["CVE"]
                        if cve:
                            self.data.append({"cve" : "Object %s index %s contains %s" % (key,index,cve)})
                            ret = True

        return ret

class RTFEmbeddedOfficeFile(Signature):
    name = "rtf_embedded_office_file"
    description = "The RTF file contains an embedded  Office file potentially to display as a decoy document during malicious activities"
    severity = 2
    confidence = 100
    categories = ["rtf", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        if "static" in self.results and "office_rtf" in self.results["static"]:
            for key in self.results["static"]["office_rtf"]:
                for block in self.results["static"]["office_rtf"][key]:
                    if "class_name" in block:
                        if "Word.Document." in block["class_name"]:
                            index = block["index"]
                            self.data.append({"office file" : "Object %s index %s contains an embedded office document" % (key,index)})
                            ret = True

        return ret

class RTFASLRBypass(Signature):
    name = "rtf_aslr_bypass"
    description = "The RTF file contains a potential ASLR bypass"
    severity = 3
    confidence = 50
    categories = ["rtf", "static", "exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        aslrbypass = [
            "otkloadr.wrassembly.1",
            "otkloadr.wrloader.1",
        ]

        ret = False
        if "static" in self.results and "office_rtf" in self.results["static"]:
            for key in self.results["static"]["office_rtf"]:
                for block in self.results["static"]["office_rtf"][key]:
                    if "class_name" in block:
                        for bypass in aslrbypass:
                            classname = block["class_name"]
                            index = block["index"]
                            if bypass in classname.lower():
                                self.data.append({"aslr bypass" : "Object %s index %s contains possible ASLR bypass %s" % (key,index,classname)})
                                ret = True

        return ret

class RTFAnomalyCharacterSet(Signature):
    name = "rtf_anomaly_characterset"
    description = "The RTF file has an unknown character set"
    severity = 2
    confidence = 100
    categories = ["office", "rtf", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        if "file" in self.results["target"]:
            filetype = self.results["target"]["file"]["type"]
            if "Rich Text Format" in filetype and "unknown character set" in filetype:
                ret = True

        return ret

class RTFAnomalyVersion(Signature):
    name = "rtf_anomaly_version"
    description = "The RTF file has an unknown version"
    severity = 2
    confidence = 100
    categories = ["office", "rtf", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        if "file" in self.results["target"]:
            filetype = self.results["target"]["file"]["type"]
            if "Rich Text Format" in filetype and "unknown version" in filetype:
                ret = True

        return ret
