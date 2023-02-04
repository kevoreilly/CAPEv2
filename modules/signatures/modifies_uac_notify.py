# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class ModifiesUACNotify(Signature):
    name = "modify_uac_prompt"
    description = "Attempts to modify UAC prompt behavior"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1088"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1548", "T1548.002"]  # MITRE v7,8
    mbcs = ["E1112"]

    def run(self):
        reg_indicators = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\ConsentPromptBehaviorAdmin$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\ConsentPromptBehaviorUser$",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\PromptOnSecureDesktop$",
        ]

        for indicator in reg_indicators:
            if self.check_write_key(pattern=indicator, regex=True):
                return True

        return False
