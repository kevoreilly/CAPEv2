# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Authenticode(Signature):
    name = "static_authenticode"
    description = "Presents an Authenticode digital signature"
    severity = 1
    weight = -1
    confidence = 30
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        found_sig = False

        if "static" in self.results and "pe" in self.results["static"]:
            if "digital_signers" in self.results["static"]["pe"] and self.results["static"]["pe"]["digital_signers"]:
                for sign in self.results["static"]["pe"]["digital_signers"]:
                    self.data.append(sign)
                    found_sig = True

        return found_sig
