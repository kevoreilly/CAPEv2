# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class EmailStealer(Signature):
    name = "infostealer_mail"
    description = "Harvests information related to installed mail clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1081", "T1003", "T1005"]

    def run(self):
        office_pkgs = ["ppt","doc","xls","eml"]
        if any(e in self.results["info"]["package"] for e in office_pkgs):
            return False

        file_indicators = [
            ".*\.pst$",
            ".*\\\\Microsoft\\\\Windows\\ Live\\ Mail.*",
            ".*\\\\Microsoft\\\\Address\\ Book\\\\.*\.wab$",
            ".*\\\\Microsoft\\\\Outlook\\ Express\\\\.*\.dbx$",
            ".*\\\\Foxmail\\\\mail\\\\.*\\\\Account\.stg$",
            ".*\\\\Foxmail.*\\\\Accounts\.tdat$",
            ".*\\\\Thunderbird\\\\Profiles\\\\.*\.default$",
            ".*\\\\AppData\\\\Roaming\\\\Thunderbird\\\\profiles.ini$",
        ]
        registry_indicators = [
            ".*\\\\Microsoft\\\\Windows\\ Messaging\\ Subsystem\\\\MSMapiApps.*",
            ".*\\\\Microsoft\\\\Windows\\ Messaging\\ Subsystem\\\\Profiles.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\ Messaging\\ Subsystem\\\\Profiles.*",
            ".*\\\\Microsoft\\\\Office\\\\.*\\\\Outlook\\\\Profiles\\\\Outlook.*",
            ".*\\\\Microsoft\\\\Office\\\\Outlook\\\\OMI\\ Account\\ Manager\\\\Accounts.*",
            ".*\\\\Microsoft\\\\Internet\\ Account\\ Manager\\\\Accounts.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?IncrediMail.*"
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\ Live\\ Mail.*",
        ]
        if self.results["target"]["category"] == "file":
            registry_indicators.append(".*\\\\Software\\\\(Wow6432Node\\\\)?Clients\\\\Mail.*")
            
        found_stealer = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file" : match })
                found_stealer = True
        for indicator in registry_indicators:
            key_match = self.check_key(pattern=indicator, regex=True, all=True)
            if key_match:
                for match in key_match:
                    self.data.append({"key" : match })
                found_stealer = True
        return found_stealer
