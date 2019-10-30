# Copyright (C) 2015-2016 KillerInstinct, Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAnalysisDetectFile(Signature):
    name = "antianalysis_detectfile"
    description = "Attempts to identify installed analysis tools by a known file location"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct", "Brad Spengler"]
    minimum = "1.2"
    ttp = ["T1063"]

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
        ]
        ret = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file" : match })
                ret = True
        return ret
