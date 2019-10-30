# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesBrowserWarn(Signature):
    name = "disables_browser_warn"
    description = "Attempts to disable browser security warnings"
    severity = 3
    categories = ["generic", "banker", "clickfraud"]
    authors = ["Optiv", "Kevin Ross"]
    minimum = "1.2"
    ttp = ["T1089"]

    def run(self):
        indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnBadCertRecving$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnBadCertSending$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnHTTPSToHTTPRedirect$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnZoneCrossing$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\WarnOnPostRedirect$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet\\ Settings\\\\IEHardenIENoWarn$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Main\\\\NoProtectedModeBanner$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Main\\\\IE9RunOncePerInstallCompleted$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet\\ Explorer\\\\Main\\\\IE9TourShown$",
            ]
        found_match = False
        for indicator in indicators:
            key_match = self.check_write_key(pattern=indicator, regex=True)
            if key_match:
                self.data.append({"key" : key_match})
                found_match = True
        return found_match
