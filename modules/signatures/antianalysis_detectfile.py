# Copyright (C) 2015-2016 KillerInstinct, Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAnalysisDetectFile(Signature):
    name = "antianalysis_detectfile"
    description = "Attempts to identify installed analysis tools by a known file location"
    severity = 3
    categories = ["anti-analysis", "discovery"]
    authors = ["KillerInstinct", "Brad Spengler", "ditekshen"]
    minimum = "1.2"
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1083", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0007", "B0013", "B0013.008", "E1083"]
    mbcs += ["OC0001", "C0051"]  # micro-behaviour

    def run(self):
        file_indicators = [
            "^[A-Za-z]:\\\\analysis",
            "^[A-Za-z]:\\\\iDEFENSE",
            "^[A-Za-z]:\\\\stuff\\\\odbg110",
            "^[A-Za-z]:\\\\gnu\\bin",
            "^[A-Za-z]:\\\\Virus\\ Analysis",
            "^[A-Za-z]:\\\\popupkiller\.exe$",
            "^[A-Za-z]:\\\\tools\\\\execute\.exe$",
            "^[A-Za-z]:\\\\MDS\\\\WinDump\.exe$",
            "^[A-Za-z]:\\\\MDS\\\\WinDump\.exe$",
            "^[A-Za-z]:\\\\guest_tools\\\\start\.bat$",
            "^[A-Za-z]:\\\\tools\\\\aswsnx",
            "^[A-Za-z]:\\\\tools\\\\decodezeus",
            "^[A-Za-z]:\\\\tool\\\\malmon",
            "^[A-Za-z]:\\\\sandcastle\\\\tools",
            "^[A-Za-z]:\\\\tsl\\\\raptorclient\.exe$",
            "^[A-Za-z]:\\\\kit\\\\procexp\.exe$",
            "^[A-Za-z]:\\\\winap\\\\ckmon\.pyw$",
            "^[A-Za-z]:\\\\vmremote\\\\vmremoteguest\.exe$",
            "^[A-Za-z]:\\\\Program\\ Files(\\ \(x86\))?\\\\Fiddler",
            "^[A-Za-z]:\\\\ComboFix",
            "^[A-Za-z]:\\\\Program\\ Files(\\ \(x86\))?\\\\FFDec",
            "^[A-Za-z]:\\\\Program\\ Files(\\ \(x86\))?\\\\Wireshark",
            "^[A-Za-z]:\\\\bin\\\\AHookMonitor\.dll$",
            "^[A-Za-z]:\\\\bin\\\\hookanaapp\.exe$",
            "^[A-Za-z]:\\\\bsa\\\\log_api",
            "^[A-Za-z]:\\\\AVCTestSuite\\\\AVCTestSuite\.exe$",
            "^[A-Za-z]:\\\\ipf\\\\BDCore_U\.dll$",
            "^[A-Za-z]:\\\\Kit\\\\procexp\.exe$",
            "^[A-Za-z]:\\\\manual\\\\grabme\.exe$",
            "^[A-Za-z]:\\\\manual\\\\SilipTCPIP\.exe$",
            "^[A-Za-z]:\\\\MWS\\\\bin\\\\agent",
            "^[A-Za-z]:\\\\original\\\\AutoRepGui",
            "^[A-Za-z]:\\\\totalcmd\\\\gfiles",
            "^[A-Za-z]:\\\\tracer\\\\FortiTracer\.exe$",
            "^[A-Za-z]:\\\\tracer\\\\mdare32_0\.sys$",
            "^[A-Za-z]:\\\\plugins\\\\(import|process)\\\\.*\.dll$",
            "^[A-Za-z]:\\\\sandbox_svc",
        ]
        ret = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file": match})
                ret = True
        return ret
