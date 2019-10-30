# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class PoisonIvyMutexes(Signature):
    name = "rat_poisonivy_mutexes"
    description = "Creates known Poison Ivy mutexes"
    severity = 3
    categories = ["rat"]
    authors = ["Optiv"]
    references = ["http://www.fireeye.com/resources/pdfs/fireeye-poison-ivy-report.pdf"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ")!VoqA.I4",
            "K^DJA^#FE",
            "KEIVH^#$S",
            "%1Sjfhtd8",
            "2SF#@R@#!"
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator):
                return True

        return False
