# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAnalysisDetectReg(Signature):
    name = "antianalysis_detectreg"
    description = "Attempts to identify installed analysis tools by registry key"
    severity = 3
    categories = ["anti-analysis", "discovery"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1012", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0007", "B0013"]
    mbcs += ["OC0008", "C0036", "C0036.003"]  # micro-behaviour

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Wireshark\.exe$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Wireshark$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler\.exe$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\Fiddler2\.exe$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Fiddler2$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Fiddler2$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\SOFTWARE\\\\IEInspectorSoft.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzer\.HTTPAnalyzerAddon$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\IEHTTPAnalyzerStd\.HTTPAnalyzerStandAlone$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Charles\.AMF\.Document$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?XK72\\ Ltd\\ folder$",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"regkey": match})
                found = True
        return found
