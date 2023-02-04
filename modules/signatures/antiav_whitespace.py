# Copyright (C) 2010-2021 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAVWhitespace(Signature):
    name = "antiav_whitespace"
    description = "Additional whitespace added to commands to avoid string detection"
    severity = 2
    categories = ["anti-av"]
    authors = ["@CybercentreCanada"]
    minimum = "1.3"
    ttps = ["T1027"]

    def run(self):
        indicator = "\s{10,}"

        matches = self.check_executed_command(pattern=indicator, regex=True, all=True)
        if matches:
            for match in matches:
                self.data.append({"command": match})

        if len(self.data) > 0:
            return True
        else:
            return False
