# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ModifiesCerts(Signature):
    name = "modifies_certs"
    description = "Attempts to create or modify system certificates"
    severity = 3
    categories = ["browser"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttp = ["T1112"]

    filter_analysistypes = set(["file"])

    def run(self):
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\SystemCertificates\\\\.*\\\\Certificates\\\\.*", regex=True):
            return True

        return False
