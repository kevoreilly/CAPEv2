# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ModifySecurityCenterWarnings(Signature):
    name = "modify_security_center_warnings"
    description = "Attempts to modify or disable Security Center warnings"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"
    ttp = ["T1031", "T1089"]

    def run(self):
        indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ NT\\\\Security\\ Center\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\explorer\\\\ShellServiceObjects\\\\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}$",
        ]                                                                                                   
        for indicator in indicators:
            if self.check_write_key(pattern=indicator, regex=True):
                return True

        return False
